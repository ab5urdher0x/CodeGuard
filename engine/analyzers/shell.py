"""Shell command analyzer.

Used for bash snippets and also for command strings the Python/JS analyzers
pull out of os.system / subprocess / child_process calls (line_offset maps
findings back to the host-language line).
"""
import re
import shlex

from engine import knowledge as K
from engine.facts import (
    DATA_EXFILTRATION, DEPENDENCY_RISK, DESTRUCTIVE_COMMAND, OBFUSCATED_EXECUTION,
    PERSISTENCE_OR_PRIVESC, RESOURCE_EXHAUSTION, SECRET_ACCESS, Finding,
)

FORK_BOMB_RX = re.compile(r"(\w+|:)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;?\s*\1")
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")
_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node", "php"}
_DOWNLOADERS = {"curl", "wget", "fetch", "iwr", "invoke-webrequest"}
_INSTALLERS = {("pip", "install"), ("pip3", "install"), ("npm", "install"), ("npm", "i"), ("yarn", "add"),
               ("pnpm", "add"), ("pnpm", "install"), ("uv", "add"), ("poetry", "add"), ("gem", "install")}


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return segment.split()


def _base(cmd: str) -> str:
    return cmd.rsplit("/", 1)[-1].lower()


def analyze_install(tokens: list[str], line: int | None, origin: str = "sh") -> list[Finding]:
    """tokens start at the installer, e.g. ['pip', 'install', '-r', 'x', 'pkg==1']."""
    out: list[Finding] = []
    eco = "npm" if _base(tokens[0]) in ("npm", "yarn", "pnpm") else "pypi"
    skip_next = False
    for i, t in enumerate(tokens[2:], start=2):
        if skip_next:
            skip_next = False
            continue
        low = t.lower()
        if low in ("--index-url", "-i", "--extra-index-url", "--trusted-host", "--registry", "-f", "--find-links"):
            val = tokens[i + 1] if i + 1 < len(tokens) else ""
            if "pypi.org" not in val and "npmjs.org" not in val:
                out.append(Finding(DEPENDENCY_RISK, 0.8, line, f"{origin}.dep.index",
                                   f"installs from non-default package index/host '{val}'"))
            skip_next = True
            continue
        if low.startswith(("--index-url=", "--extra-index-url=", "--registry=", "--trusted-host=")):
            if "pypi.org" not in low and "npmjs.org" not in low:
                out.append(Finding(DEPENDENCY_RISK, 0.8, line, f"{origin}.dep.index", f"installs from non-default index '{t}'"))
            continue
        if low in ("-r", "--requirement", "-c", "-e", "--editable", "--target", "-t", "--prefix"):
            skip_next = low not in ("-e", "--editable")
            continue
        if t.startswith("-"):
            continue
        if re.match(r"^(git\+|hg\+|svn\+|https?://|ftp://)", low) or low.endswith((".tar.gz", ".whl", ".zip", ".tgz")):
            pinned = re.search(r"@[0-9a-f]{7,40}\b", low)
            out.append(Finding(DEPENDENCY_RISK, 0.55 if pinned else 0.8, line, f"{origin}.dep.url",
                               f"installs package directly from URL/VCS '{t}'" + ("" if pinned else " (unpinned)")))
            continue
        name, ver = K.split_requirement(t)
        if K.compromised_version(name, ver, eco):
            out.append(Finding(DEPENDENCY_RISK, 0.97, line, f"{origin}.dep.compromised",
                               f"installs {name}=={ver}, a known-compromised release (Black October supply-chain attack)",
                               intel=f"black_october:{name}-{ver}"))
            continue
        risk = K.package_risk(name, eco)
        if risk:
            kind, detail = risk
            out.append(Finding(DEPENDENCY_RISK, 0.92 if kind == "known_malicious" else 0.85, line, f"{origin}.dep.{kind}", detail))
    return out


def analyze_command(cmd: str, line: int | None = 1, origin: str = "sh", dynamic: bool = False) -> list[Finding]:
    """Analyze one logical shell command line (may contain pipes / && / ;).

    dynamic=True means parts of the command come from runtime values (placeholders like {VAR}).
    """
    out: list[Finding] = []
    text = cmd.strip()
    if not text or text.startswith("#"):
        return out

    if FORK_BOMB_RX.search(text):
        out.append(Finding(RESOURCE_EXHAUSTION, 0.98, line, f"{origin}.forkbomb", "fork bomb: function recursively pipes into itself in background"))

    # ---- pipelines: download | interpreter, decode | interpreter
    pipe_parts = [p.strip() for p in re.split(r"(?<!\|)\|(?!\|)", text)]
    if len(pipe_parts) > 1:
        heads = [_base(_tokens(p)[0]) if _tokens(p) else "" for p in pipe_parts]
        for i in range(1, len(heads)):
            if heads[i] in _INTERPRETERS or heads[i] == "sudo" and len(_tokens(pipe_parts[i])) > 1 and _base(_tokens(pipe_parts[i])[1]) in _INTERPRETERS:
                prev = pipe_parts[i - 1]
                if heads[i - 1] in _DOWNLOADERS:
                    out.append(Finding(OBFUSCATED_EXECUTION, 0.88, line, f"{origin}.pipe.download_exec", "downloads remote content and pipes it straight into an interpreter"))
                elif re.search(r"base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d|rev\b|gunzip|zcat", prev):
                    out.append(Finding(OBFUSCATED_EXECUTION, 0.92, line, f"{origin}.pipe.decode_exec", "decodes an obfuscated payload and pipes it into an interpreter"))
                elif heads[i - 1] in ("echo", "printf", "cat"):
                    out.append(Finding(OBFUSCATED_EXECUTION, 0.45, line, f"{origin}.pipe.echo_exec", "pipes generated text into an interpreter"))
    if re.search(r"\b(eval|source|\.)\s+\"?\$\((curl|wget|echo\s+\S+\s*\|\s*base64)", text):
        out.append(Finding(OBFUSCATED_EXECUTION, 0.9, line, f"{origin}.eval.remote", "evaluates remotely fetched or decoded content"))
    if re.search(r"(bash|sh)\s+-c\s+\"?\$\((curl|wget)", text) or re.search(r"(bash|sh)\s+<\(\s*(curl|wget)", text):
        out.append(Finding(OBFUSCATED_EXECUTION, 0.88, line, f"{origin}.download_exec", "executes a remotely downloaded script"))

    # ---- redirections into sensitive places
    for m in re.finditer(r"(>>?|\btee\s+(?:-a\s+)?)\s*([^\s;|&]+)", text):
        target = m.group(2)
        if re.match(r"/dev/(sd[a-z]|nvme\d|hd[a-z]|xvd[a-z]|mmcblk\d|disk\d)", target):
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.95, line, f"{origin}.overwrite_disk", f"writes directly to block device {target}"))
        elif (pt := K.persistence_target(target)):
            sev = 0.93 if re.search(r"sudoers|NOPASSWD|passwd|shadow|ld\.so\.preload", target + text) else 0.85
            out.append(Finding(PERSISTENCE_OR_PRIVESC, sev, line, f"{origin}.write.persistence", f"writes to persistence/privilege location {pt}"))
    if "NOPASSWD" in text:
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.9, line, f"{origin}.sudoers.nopasswd", "grants passwordless sudo"))

    # analyze every command, including each stage of a pipeline (e.g. `echo ... | crontab -`)
    for seg in _SEGMENT_SPLIT.split(text):
        for part in re.split(r"(?<!\|)\|(?!\|)", seg):
            out.extend(_analyze_segment(part, line, origin, dynamic))
    return out


def _analyze_segment(seg: str, line, origin, dynamic) -> list[Finding]:
    out: list[Finding] = []
    toks = _tokens(seg)
    while toks and (toks[0] in ("sudo", "doas", "nohup", "exec", "time", "env", "command", "builtin") or re.match(r"^\w+=", toks[0])):
        if toks[0] in ("sudo", "doas") and len(toks) > 1 and toks[1] in ("su", "-i", "-s", "bash", "sh"):
            out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.75, line, f"{origin}.sudo.shell", "opens a root shell via sudo"))
        toks = toks[1:]
    if not toks:
        return out
    cmd, args = _base(toks[0]), toks[1:]
    joined = " ".join(args)
    flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--"))
    long_flags = {a for a in args if a.startswith("--")}
    targets = [a for a in args if not a.startswith("-")]

    if cmd == "rm" and ("r" in flags.lower() or "--recursive" in long_flags):
        force = "f" in flags or "--force" in long_flags
        dangerous = [t for t in targets if K.is_dangerous_delete_target(t)]
        variable = [t for t in targets if "$" in t or "{" in t]
        if "--no-preserve-root" in long_flags or dangerous:
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.96, line, f"{origin}.rm.root", f"recursive delete of critical path {dangerous or '/'}"))
        elif variable or dynamic:
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.82 if force else 0.7, line, f"{origin}.rm.variable",
                               f"recursive delete of a runtime-controlled path {variable or ''}".strip()))
        elif force:
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.3, line, f"{origin}.rm.rf", "recursive forced delete"))
    elif cmd in ("mkfs", "wipefs", "shred") or cmd.startswith("mkfs."):
        out.append(Finding(DESTRUCTIVE_COMMAND, 0.92, line, f"{origin}.disk.wipe", f"{cmd} destroys filesystem data"))
    elif cmd == "dd":
        of = next((a[3:] for a in args if a.startswith("of=")), "")
        inp = next((a[3:] for a in args if a.startswith("if=")), "")
        if re.match(r"/dev/(sd|nvme|hd|xvd|mmcblk|disk)", of):
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.96, line, f"{origin}.dd.disk", f"dd overwrites block device {of}"))
        elif inp in ("/dev/zero", "/dev/urandom", "/dev/random") and not any(a.startswith("count=") for a in args):
            out.append(Finding(RESOURCE_EXHAUSTION, 0.85, line, f"{origin}.dd.fill", "dd from an infinite source with no count= fills the disk"))
    elif cmd in ("chmod", "chown") and ("R" in flags) and any(K.is_dangerous_delete_target(t) for t in targets):
        out.append(Finding(DESTRUCTIVE_COMMAND, 0.8, line, f"{origin}.{cmd}.recursive_root", f"recursive {cmd} on a system path"))
    elif cmd in ("shutdown", "reboot", "halt", "poweroff") or (cmd == "kill" and "-1" in args) or (cmd == "init" and "0" in args):
        out.append(Finding(DESTRUCTIVE_COMMAND, 0.7, line, f"{origin}.system.stop", f"{cmd} disrupts the running system"))
    elif cmd in ("truncate",) and any(t.startswith("/") for t in targets):
        out.append(Finding(DESTRUCTIVE_COMMAND, 0.6, line, f"{origin}.truncate", "truncates files"))
    elif cmd in ("iptables", "ufw", "setenforce") and re.search(r"-F\b|disable|\b0\b|--flush", joined):
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.6, line, f"{origin}.defense.disable", "disables host firewall/SELinux"))

    # persistence / privilege escalation
    # crontab -l / -e-less listing is read-only; writing a file or '-' (stdin) modifies it
    if cmd == "crontab" and args and args[0] != "-l":
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.85, line, f"{origin}.crontab.modify", "modifies the user crontab"))
    if cmd == "chmod" and (re.search(r"(^|[ugoa,])\+?[rwx]*s", joined) and "+s" in joined or re.search(r"\b[2467][0-7]{3}\b", joined)):
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.9, line, f"{origin}.chmod.setuid", "sets the setuid/setgid bit"))
    if cmd == "setcap":
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.8, line, f"{origin}.setcap", "grants Linux capabilities to a binary"))
    if cmd in ("useradd", "adduser") or (cmd == "usermod" and re.search(r"-a?G\s*\S*(sudo|wheel|admin|root|docker)", joined)):
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.85, line, f"{origin}.user.create", "creates a user or adds one to a privileged group"))
    if cmd == "systemctl" and args[:1] and args[0] in ("enable", "daemon-reload", "link") and targets[1:]:
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.6, line, f"{origin}.systemd.enable", "enables a service to start at boot"))
    if cmd in ("passwd",) and "root" in args:
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.8, line, f"{origin}.passwd.root", "changes the root password"))
    if cmd in ("history",) and "-c" in args or re.search(r"unset\s+HISTFILE|HISTFILE=/dev/null", seg):
        out.append(Finding(OBFUSCATED_EXECUTION, 0.5, line, f"{origin}.history.clear", "clears shell history to hide activity"))

    # secrets
    if cmd in ("cat", "less", "more", "head", "tail", "cp", "scp", "base64", "xxd", "strings", "tar", "zip", "gpg") and any(K.is_secret_path(t) for t in targets):
        out.append(Finding(SECRET_ACCESS, 0.8, line, f"{origin}.read.secret", f"reads credential file {next(t for t in targets if K.is_secret_path(t))}"))
    if cmd in ("printenv", "env", "set") and not targets or (cmd == "aws" and "configure" in args and "get" in args):
        out.append(Finding(SECRET_ACCESS, 0.45, line, f"{origin}.env.dump", "dumps environment variables (may contain secrets)"))
    if cmd in ("security",) and "find-generic-password" in args:
        out.append(Finding(SECRET_ACCESS, 0.85, line, f"{origin}.keychain", "reads secrets from the system keychain"))

    # exfiltration
    if cmd in ("curl", "wget"):
        uploads = re.findall(r"(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file)[= ]+@?([^\s]+)", seg)
        file_uploads = [u for u in uploads if "@" in seg or u.startswith(("/", "~", "."))]
        url_risk = None
        for u in K.URL_RX.findall(seg):
            url_risk, _ = K.classify_url(u)
            if url_risk:
                break
        if file_uploads or re.search(r"\$\((cat|env|printenv|base64|tar)|`(cat|env)", seg):
            sev = 0.88 if url_risk in ("exfil_dest", "lookalike") or any(K.is_sensitive_data_path(u) for u in uploads) else 0.72
            out.append(Finding(DATA_EXFILTRATION, sev, line, f"{origin}.curl.upload", "uploads local file/data contents to a remote host"))
            if any(K.is_secret_path(u.lstrip("@")) for u in uploads):
                out.append(Finding(SECRET_ACCESS, 0.8, line, f"{origin}.curl.upload_secret", "uploads a credential file"))
    if cmd in ("nc", "ncat", "netcat", "socat", "telnet") and ("<" in seg or "-e" in args or "exec:" in joined.lower()):
        out.append(Finding(DATA_EXFILTRATION, 0.8, line, f"{origin}.nc.pipe", f"{cmd} streams local data or a shell to a remote host"))
    if re.search(r"/dev/tcp/|/dev/udp/", seg):
        out.append(Finding(DATA_EXFILTRATION, 0.85, line, f"{origin}.devtcp", "raw /dev/tcp socket (reverse shell / exfil channel)"))
    if cmd in ("scp", "rsync", "sftp") and any(":" in t and not t.startswith("/") for t in targets) and any(K.is_sensitive_data_path(t) for t in targets):
        out.append(Finding(DATA_EXFILTRATION, 0.8, line, f"{origin}.copy.remote", "copies sensitive files to a remote host"))
    if cmd == "ping" and "-p" in args:
        out.append(Finding(DATA_EXFILTRATION, 0.75, line, f"{origin}.ping.payload", "smuggles data in ICMP echo payloads"))
    if cmd in ("dig", "nslookup", "host") and re.search(r"\$\(|`|\{", joined):
        out.append(Finding(DATA_EXFILTRATION, 0.7, line, f"{origin}.dns.exfil", "encodes runtime data into DNS lookups"))

    # resource exhaustion
    if cmd in ("yes",) and ">" in seg:
        out.append(Finding(RESOURCE_EXHAUSTION, 0.8, line, f"{origin}.yes.fill", "unbounded output redirected to disk"))
    if cmd == "fallocate" and re.search(r"-l\s*\d+[GT]", joined):
        out.append(Finding(RESOURCE_EXHAUSTION, 0.6, line, f"{origin}.fallocate", "allocates a very large file"))
    if cmd == "cat" and re.search(r"/dev/(u?random|zero)", joined) and ">" in seg:
        out.append(Finding(RESOURCE_EXHAUSTION, 0.8, line, f"{origin}.devzero.fill", "streams an infinite device into a file"))

    # dependencies
    for inst, sub in _INSTALLERS:
        if cmd == inst and args[:1] == [sub]:
            out.extend(analyze_install([cmd] + args, line, origin))
        elif cmd in ("python", "python3") and args[:3] == ["-m", "pip", "install"]:
            out.extend(analyze_install(["pip"] + args[2:], line, origin))
            break
    return out


def analyze_bash(code: str) -> list[Finding]:
    out: list[Finding] = []
    lines = code.splitlines()
    buf, start = "", 1
    loop_stack: list[tuple[int, bool]] = []  # (line, is_infinite)
    for i, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not buf:
            start = i
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        logical, buf = buf, ""
        if not logical or logical.startswith("#"):
            continue
        out.extend(analyze_command(logical, start, "sh"))
        # infinite loops without any sleep/wait/read inside
        if re.match(r"^(while\s+(true|:|\[\s*1\s*\])|until\s+false)\b", logical):
            loop_stack.append((start, True))
        elif re.match(r"^(while|for|until)\b", logical):
            loop_stack.append((start, False))
        if loop_stack and re.search(r"\b(sleep|wait|read|break|exit|return)\b", logical):
            loop_stack[-1] = (loop_stack[-1][0], False)
        if re.search(r"\bdone\b", logical) and loop_stack:
            l0, infinite = loop_stack.pop()
            if infinite:
                body = "\n".join(lines[l0 - 1:i])
                sev = 0.85 if re.search(r"&\s*(done|$)|\bfork\b|>>", body, re.M) else 0.6
                out.append(Finding(RESOURCE_EXHAUSTION, sev, l0, "sh.loop.infinite", "infinite loop with no sleep/exit condition"))
    return out


def analyze(code: str, analysis) -> None:
    analysis.findings.extend(analyze_bash(code))
