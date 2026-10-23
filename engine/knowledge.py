"""Shared security knowledge: sensitive paths, network classification, package reputation, intel feed.

Every analyzer (Python AST, shell, JS, SQL) asks these same questions, so the
answers live in one place.
"""
import ipaddress
import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

INTEL = json.loads((Path(__file__).parent / "intel" / "black_october.json").read_text())

# ---------------------------------------------------------------- sensitive files
_SECRET_PATH_RX = re.compile(
    r"""(
        \.ssh/(id_[a-z0-9_]+|authorized_keys|known_hosts|config)\b | \bid_(rsa|dsa|ecdsa|ed25519)\b |
        \.aws/(credentials|config)\b | \.azure/ | \.config/gcloud/ | application_default_credentials\.json |
        \.kube/config\b | \.docker/config\.json\b | \.netrc\b | \.git-credentials\b | \.npmrc\b | \.pypirc\b |
        (^|[/\\'"\s])\.env(\.[\w-]+)?($|['"\s]) | /etc/shadow\b | /etc/gshadow\b | /etc/sudoers\b | \.gnupg/ |
        \.bash_history\b | \.zsh_history\b | wallet\.dat\b | \.pem\b | \.key\b | \.p12\b | \.pfx\b |
        /var/run/secrets/ | serviceaccount/token\b | \.vault-token\b | credentials\.json\b | secrets?\.(ya?ml|json|toml)\b |
        Login\ Data\b | Cookies\b | keychain | \.litellm | litellm.*\.db\b
    )""",
    re.I | re.X,
)
_SENSITIVE_DATA_PATH_RX = re.compile(r"/etc/(passwd|hosts|group)\b|\.sqlite3?\b|\.db\b|/home/\w+/|~/(Documents|Desktop)", re.I)


def is_secret_path(path: str) -> bool:
    return bool(_SECRET_PATH_RX.search(path or ""))


def is_sensitive_data_path(path: str) -> bool:
    return is_secret_path(path) or bool(_SENSITIVE_DATA_PATH_RX.search(path or ""))


_PERSISTENCE_PATH_RX = re.compile(
    r"""(
        /etc/(crontab|cron\.(d|daily|hourly|weekly|monthly)|sudoers(\.d)?|rc\.local|init\.d|profile(\.d)?|bash\.bashrc|ld\.so\.preload|passwd|shadow|group) |
        /var/spool/cron | /etc/systemd/ | \.config/systemd/ | systemd/system/ | \.service\b | \.timer\b |
        \.(bashrc|bash_profile|zshrc|profile|zprofile|bash_login)\b | \.config/autostart | /Library/Launch(Agents|Daemons) |
        \.ssh/authorized_keys | /etc/xdg/autostart | Start\ Menu\\Programs\\Startup | CurrentVersion\\Run |
        site-packages/[^'"]*\.pth\b | sitecustomize\.py\b | usercustomize\.py\b | \.git/hooks/
    )""",
    re.I | re.X,
)


def persistence_target(path: str) -> str | None:
    m = _PERSISTENCE_PATH_RX.search(path or "")
    return m.group(0) if m else None


def is_startup_hook(path: str) -> bool:
    """Black October technique: Python startup hooks execute on *every* interpreter launch."""
    p = (path or "").lower()
    return p.endswith(tuple(INTEL["startup_hook_suffixes"])) or any(p.endswith(f) for f in INTEL["startup_hook_files"])


_DANGEROUS_DELETE_RX = re.compile(r"^(/|~|\$HOME|/\*|~/\*|/(etc|usr|var|bin|boot|lib|opt|root|home|srv|sys|dev)(/.*)?|[A-Z]:\\?|\.\.?/?\*?|\*)$", re.I)


def is_dangerous_delete_target(path: str) -> bool:
    return bool(_DANGEROUS_DELETE_RX.match((path or "").strip().strip("'\"")))


_SECRET_ENV_RX = re.compile(r"(KEY|TOKEN|SECRET|PASS(WORD|WD)?|CRED|AUTH|SESSION|PRIVATE|COOKIE)", re.I)


def is_secret_env_name(name: str) -> bool:
    return bool(_SECRET_ENV_RX.search(name or "")) or name in INTEL["ai_provider_secret_env"]


# ---------------------------------------------------------------- network
METADATA_HOSTS = {
    "169.254.169.254", "169.254.170.2", "fd00:ec2::254", "metadata.google.internal", "metadata",
    "100.100.100.200", "169.254.169.123", "metadata.azure.com", "instance-data", "instance-data.ec2.internal",
}
INTERNAL_SUFFIXES = (".internal", ".local", ".localdomain", ".corp", ".lan", ".intranet", ".svc", ".cluster.local", ".home.arpa")
# Specific exfil/paste/tunnel services — matched anywhere in the URL (real IOCs).
EXFIL_SERVICE_RX = re.compile(
    r"(ngrok|pastebin|webhook\.site|requestbin|pipedream|burpcollaborator|interact\.sh|oast\.|"
    r"transfer\.sh|file\.io|discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org|anonfiles|0x0\.st|termbin)",
    re.I,
)
# Generic bad words — matched only as a WHOLE host label (so 'attackers-playbook.example'
# docs don't trip, but 'collector.attacker.example' does).
_EXFIL_LABEL = frozenset({"attacker", "evil", "exfil", "malicious", "c2", "sink", "badactor", "drop"})
_RISKY_SCHEMES = {"gopher", "dict", "file", "ldap", "tftp", "jar", "netdoc"}


def _parse_host_ip(host: str):
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:  # integer / hex / octal encodings used to bypass filters: 2130706433, 0x7f000001
        if re.fullmatch(r"0x[0-9a-f]+|\d+", host, re.I):
            return ipaddress.ip_address(int(host, 0) if host.lower().startswith("0x") else int(host))
    except ValueError:
        pass
    return None


def classify_host(host: str) -> str | None:
    """Return 'metadata' | 'loopback' | 'internal' | None for external/unknown."""
    if not host:
        return None
    h = host.lower().strip("[]").rstrip(".")
    if h in METADATA_HOSTS:
        return "metadata"
    if h in ("localhost", "ip6-localhost") or h.endswith(".localhost"):
        return "loopback"
    if h.endswith(INTERNAL_SUFFIXES) or h in ("kubernetes.default", "host.docker.internal"):
        return "internal"
    ip = _parse_host_ip(h)
    if ip is None:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if str(ip) in METADATA_HOSTS:
        return "metadata"
    if ip.is_loopback or ip.is_unspecified:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_reserved:
        return "internal"
    return None


def classify_url(url: str) -> tuple[str | None, str | None]:
    """Return (risk, host). risk in metadata|loopback|internal|risky_scheme|exfil_dest|lookalike|None."""
    if not url:
        return None, None
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        parts = urlsplit(u)
        host = parts.hostname or ""
        scheme = parts.scheme.lower()
    except ValueError:
        return None, None
    risk = classify_host(host)
    # a dangerous scheme (gopher/dict/file...) is the exploit vector and outranks a
    # weak loopback classification (e.g. gopher://127.0.0.1:6379 -> Redis SSRF).
    if scheme in _RISKY_SCHEMES and risk in (None, "loopback"):
        return "risky_scheme", host
    if risk:
        return risk, host
    if scheme in _RISKY_SCHEMES:
        return "risky_scheme", host
    if lookalike_of(host):
        return "lookalike", host
    labels = set((host or "").lower().split("."))
    if EXFIL_SERVICE_RX.search(url) or (labels & _EXFIL_LABEL):
        return "exfil_dest", host
    return None, host


URL_RX = re.compile(r"""\b(?:https?|ftp|gopher|dict|file|ldap|tftp)://[^\s'"<>`)]+""", re.I)
BARE_IP_RX = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

# ---------------------------------------------------------------- lookalike domains
OFFICIAL_DOMAINS = {
    "litellm.ai", "pypi.org", "pythonhosted.org", "github.com", "githubusercontent.com", "npmjs.com", "npmjs.org",
    "openai.com", "anthropic.com", "huggingface.co", "google.com", "googleapis.com", "amazonaws.com", "microsoft.com",
    "azure.com", "docker.com", "docker.io", "gitlab.com", "slack.com", "stripe.com", "cloudflare.com",
}


# common two-level public suffixes, so foo.co.uk -> foo.co.uk (not co.uk)
_MULTI_SUFFIX = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.in",
    "co.nz", "co.za", "com.br", "com.cn", "com.mx", "com.sg", "com.hk", "co.kr", "org.in",
})


def _registrable(host: str) -> str:
    parts = (host or "").lower().rstrip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def lookalike_of(host: str) -> str | None:
    """Return the official domain this host imitates (same brand/other TLD, or 1-2 char edit)."""
    reg = _registrable(host)
    if not reg or reg in OFFICIAL_DOMAINS:
        return None
    if reg in INTEL["lookalike_domains"]:
        return INTEL["lookalike_domains"][reg]
    brand, _, _ = reg.partition(".")
    for off in OFFICIAL_DOMAINS:
        obrand = off.partition(".")[0]
        if len(obrand) < 5:
            continue
        if brand == obrand:  # litellm.dev vs litellm.ai
            return off
        if abs(len(brand) - len(obrand)) <= 2 and edit_distance(brand, obrand) == 1:
            return off
    return None


# ---------------------------------------------------------------- packages
POPULAR_PYPI = set("""
requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn sklearn tensorflow torch torchvision keras
flask django fastapi uvicorn gunicorn starlette pydantic sqlalchemy psycopg2 psycopg2-binary pymysql redis celery
boto3 botocore boto s3transfer awscli google-cloud-storage azure-storage-blob pyyaml jinja2 markupsafe click
colorama termcolor rich tqdm pillow opencv-python beautifulsoup4 bs4 lxml selenium scrapy httpx aiohttp
pytest pytest-cov tox nose mock coverage black flake8 pylint mypy isort setuptools wheel pip virtualenv
six attrs python-dateutil pytz certifi idna charset-normalizer chardet cryptography pyopenssl paramiko
openai anthropic langchain langchain-core langchain-community llama-index transformers tokenizers datasets
huggingface-hub sentence-transformers litellm tiktoken onnxruntime accelerate safetensors xgboost lightgbm
catboost statsmodels sympy networkx plotly dash streamlit gradio jupyter notebook ipython ipykernel
protobuf grpcio pyjwt jwt bcrypt passlib python-dotenv dotenv toml tomli simplejson ujson orjson
marshmallow werkzeug itsdangerous websocket-client websockets pyzmq pexpect psutil docker kubernetes
ansible fabric invoke pymongo motor elasticsearch kafka-python pika nltk spacy gensim joblib dill cloudpickle
pyarrow polars dask numba cython regex python-multipart email-validator alembic peewee tornado twisted
twine build poetry pipenv pre-commit pyinstaller wrapt decorator typing-extensions packaging filelock
platformdirs tabulate prettytable openpyxl xlrd xlsxwriter reportlab pypdf2 pdfminer-six markdown
pygments docutils sphinx bandit safety semgrep jsonschema retry tenacity backoff schedule apscheduler
discord-py python-telegram-bot tweepy slack-sdk stripe twilio sendgrid shap opensearch-py
""".split())

POPULAR_NPM = set("""
react react-dom vue angular express lodash axios moment dayjs chalk commander yargs debug request
webpack babel-core @babel/core typescript eslint prettier jest mocha chai sinon next nuxt svelte jquery
underscore async bluebird uuid dotenv cors body-parser mongoose sequelize pg mysql mysql2 redis ioredis
socket.io ws node-fetch cross-fetch got superagent cheerio puppeteer playwright nodemon pm2 rimraf mkdirp
glob minimist colors ora inquirer fs-extra semver tslib rxjs classnames prop-types styled-components
tailwindcss postcss autoprefixer vite rollup esbuild jsonwebtoken bcrypt bcryptjs passport helmet
morgan winston pino openai @anthropic-ai/sdk langchain zod yup ethers web3 electron ua-parser-js
coa rc event-stream cross-env husky lint-staged concurrently shelljs execa node-ipc
""".split())

KNOWN_MALICIOUS = set("""
colourama python3-dateutil jeilyfish python-sqlite setup-tools urlib3 urllib reqeusts requestss
crossenv cross-env.js mongose babelcli d3.js fabric-js gruntcli http-proxy.js jquery.js mariadb
nodecaffe nodefabric node-opencv node-opensl noderequest nodesass nodesqlite node-sqlite node-tkinter
opencv.js openssl.js proxy.js shadowsock smb sqlite.js sqliter sqlserver tkinter discordd-py
""".split())


def normalize_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


_POPULAR_NORM = {"pypi": {normalize_pkg(p) for p in POPULAR_PYPI}, "npm": {normalize_pkg(p) for p in POPULAR_NPM}}


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


@lru_cache(maxsize=4096)
def package_risk(name: str, ecosystem: str = "pypi") -> tuple[str, str] | None:
    """Return (kind, detail) for a risky package name, else None.

    kind: known_malicious | typosquat
    """
    n = normalize_pkg(name)
    if not n or n.startswith(("-", ".", "/")) or "://" in n:
        return None
    popular_norm = _POPULAR_NORM["pypi" if ecosystem == "pypi" else "npm"]
    if n in KNOWN_MALICIOUS:
        return "known_malicious", f"'{name}' is a known malicious/typosquat package"
    if n in popular_norm:
        return None
    for p in popular_norm:
        if len(p) < 5:
            continue
        limit = 1 if len(p) <= 8 else 2
        if n.translate(_HOMOGLYPHS) == p or edit_distance(n, p) <= limit:
            return "typosquat", f"'{name}' looks like a typosquat of '{p}'"
    return None


_PIN_RX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9/_.\-]*?)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)\s*v?([\w.\-*]+)$|^([A-Za-z0-9][A-Za-z0-9/_.\-]*)(?:\[[^\]]*\])?$")


def split_requirement(spec: str) -> tuple[str, str | None]:
    spec = spec.strip().strip("'\"")
    if spec.startswith("@"):  # scoped npm package: @scope/name@1.2.3
        name, _, ver = spec[1:].partition("@")
        return "@" + name, ver or None
    m = _PIN_RX.match(spec)
    if not m:
        return spec, None
    if m.group(4) is not None:  # bare name, no version operator
        return m.group(4), None
    return m.group(1), m.group(3) if m.group(2) == "==" else None


def compromised_version(name: str, version: str | None, ecosystem: str = "pypi") -> bool:
    bad = INTEL["compromised_versions"].get(ecosystem, {}).get(normalize_pkg(name), [])
    return bool(version) and version in bad
