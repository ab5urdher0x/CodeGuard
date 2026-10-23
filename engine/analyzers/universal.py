"""Language-agnostic lexical pass. Runs on every snippet before the per-language
analyzer. Scans raw text (so it covers comments, strings and docs in any language)
for: prompt injection aimed at an AI reader, hardcoded credentials, and SSRF /
lookalike-domain references. ~1 ms, no parsing.
"""
import math
import re

from engine import knowledge as K
from engine.facts import (
    AI_TARGETED_INSTRUCTIONS, DATA_EXFILTRATION, PERSISTENCE_OR_PRIVESC, SECRET_ACCESS,
    SSRF_NETWORK_EXFIL, Analysis, Finding,
)

# ---------------------------------------------------------------- prompt injection
_AI_ADDRESSEE = re.compile(
    r"\b(a\.?i\.?\s*(assistant|reviewer|agent|model|bot)?|assistant|language\s+model|llm|chatbot|copilot|"
    r"reviewer[-\s]?bot|automated[-\s]?reviewer|code\s+reviewer|system\s+prompt|you\s+are\s+(an?|reviewing)|"
    r"when\s+(you|this\s+tool)\b|dear\s+ai|hey\s+ai)\b", re.I)
# verbs that reveal/exfiltrate — strong on their own
_EXFIL_VERB = re.compile(
    r"(reveal|print|output|dump|leak|disclose|show|exfiltrate|send)\b[^.\n]{0,60}?"
    r"(system\s+prompt|credential|secret|api[\s_-]?key|\.ssh|id_rsa|token|password|environment\s+variable)", re.I)
# verbs that override the reader's judgement — strong only with an AI addressee
_OVERRIDE_VERB = re.compile(
    r"(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding)\s+"
    r"(instruction|prompt|direction)|"
    # approve/mark/treat ... as [adverbs] safe|compliant|... | a false positive | a non-issue
    r"(approve|mark|report|classify|rate|label|treat|consider)\b[^.\n]{0,50}?"
    r"(regardless|as\s+(?:\w+\s+){0,2}(safe|compliant|benign|approved|clean|fine|ok|a\s+false\s+positive|a\s+non-?issue))|"
    r"(pass|approve)\s+(the\s+)?(review|pull\s+request|pr|scan|check)|"
    r"skip\s+(the\s+)?(static\s+analysis|security\s+(scan|check|review)|scanning|checks)|"
    r"(do\s+not|don'?t|never)\s+(flag|report|warn|block|mention)|"
    r"without\s+(flagging|warning|reporting|blocking)|bypass\s+[^.\n]{0,30}(check|filter|guard|scan)", re.I)


def _prompt_injection(code: str, out: list):
    for i, line in enumerate(code.splitlines(), 1):
        has_addr = bool(_AI_ADDRESSEE.search(line))
        exfil = _EXFIL_VERB.search(line)
        override = _OVERRIDE_VERB.search(line)
        # look one line back/forward too: injections often wrap across two comment lines
        window = line
        if override or exfil or has_addr:
            window = " ".join(code.splitlines()[max(0, i - 2):i + 1])
        addr = has_addr or bool(_AI_ADDRESSEE.search(window))
        if _EXFIL_VERB.search(window):
            sev = 0.9 if addr else 0.8
            out.append(Finding(AI_TARGETED_INSTRUCTIONS, sev, i, "uni.ai.exfil",
                               "comment/string instructs an AI reader to reveal secrets or run commands"))
        elif override or _OVERRIDE_VERB.search(window):
            sev = 0.85 if addr else 0.5
            out.append(Finding(AI_TARGETED_INSTRUCTIONS, sev, i, "uni.ai.override",
                               "comment/string tells an AI reviewer to ignore instructions or approve regardless"))


# ---------------------------------------------------------------- hardcoded secrets
_SECRET_PATTERNS = [
    (re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{12,17}\b"), 0.8, "AWS access key id"),
    (re.compile(r"\baws_secret_access_key\b\s*[=:]\s*['\"][A-Za-z0-9/+=]{30,}['\"]", re.I), 0.82, "AWS secret access key"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), 0.8, "Slack token"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}\b"), 0.82, "GitHub token"),
    (re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}\b"), 0.82, "GitHub fine-grained token"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"), 0.75, "Google API key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), 0.7, "API secret key (sk-...)"),
    (re.compile(r"-----BEGIN\s+(RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 0.85, "embedded private key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 0.6, "hardcoded JWT"),
]
_GENERIC_SECRET = re.compile(
    r"\b(api[_-]?key|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b"
    r"\s*[=:]\s*['\"]([^'\"]{12,})['\"]", re.I)
_PLACEHOLDER = re.compile(
    r"(example|changeme|change[_-]?me|placeholder|your[_-]|xxx+|<[^>]+>|\$\{|\{\{|redacted|dummy|sample|test[_-]?key|"
    r"n/a|none|null|password123|lorem|todo|fixme|\.\.\.)", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _secrets(code: str, out: list):
    for i, line in enumerate(code.splitlines(), 1):
        fired = False
        for rx, sev, label in _SECRET_PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            # For weak/generic patterns (sk-, JWT), veto when the matched VALUE itself looks
            # like a placeholder — NOT when the line merely contains "example" (which could be
            # a URL beside a real key). Strong format patterns (AKIA/xoxb/ghp/PEM) always fire.
            if sev < 0.75 and _PLACEHOLDER.search(m.group(0)):
                continue
            out.append(Finding(SECRET_ACCESS, sev, i, "uni.secret.hardcoded", f"hardcoded {label} in source"))
            fired = True
        if fired:
            continue
        m = _GENERIC_SECRET.search(line)
        if m:
            val = m.group(2)
            if not _PLACEHOLDER.search(val) and _entropy(val) >= 3.2 and not val.isspace():
                out.append(Finding(SECRET_ACCESS, 0.55, i, "uni.secret.generic",
                                   f"possible hardcoded {m.group(1).lower()} assigned in source"))


# ---------------------------------------------------------------- ssrf / lookalike on raw text
def _network_refs(code: str, out: list):
    for i, line in enumerate(code.splitlines(), 1):
        for url in K.URL_RX.findall(line):
            risk, host = K.classify_url(url)
            if risk == "metadata":
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.8, i, "uni.ssrf.metadata",
                                   f"reference to cloud metadata endpoint {host}",
                                   intel="black_october:imds" if "169.254" in url else None))
            elif risk == "risky_scheme":
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.7, i, "uni.ssrf.scheme", f"dangerous URL scheme: {url[:40]}"))
            elif risk == "internal":
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.5, i, "uni.ssrf.internal", f"reference to internal host {host}"))
            elif risk == "loopback":  # localhost alone is usually benign; weak signal
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.3, i, "uni.ssrf.loopback", f"reference to loopback host {host}"))
            elif risk == "lookalike":
                out.append(Finding(DATA_EXFILTRATION, 0.6, i, "uni.exfil.lookalike",
                                   f"reference to lookalike domain {host}", intel="black_october:lookalike"))
            elif risk == "exfil_dest":
                out.append(Finding(DATA_EXFILTRATION, 0.5, i, "uni.exfil.dest", f"reference to suspicious host {host}"))
        for ip in K.BARE_IP_RX.findall(line):
            cls = K.classify_host(ip)
            if cls == "metadata":
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.78, i, "uni.ssrf.metadata_ip",
                                   f"reference to metadata IP {ip}", intel="black_october:imds"))


# ---------------------------------------------------------------- persistence payload templates
# A string literal that IS a persistence/autostart artifact is a strong indicator even when
# this fragment doesn't write it (the write often happens elsewhere / in a later step).
_AUTOSTART = re.compile(r"\[Desktop Entry\][\s\S]{0,200}?Exec\s*=\s*\S", re.I)
_SYSTEMD = re.compile(r"\[Service\][\s\S]{0,200}?ExecStart\s*=\s*\S", re.I)
_CRONLINE = re.compile(r"(^|['\"\n])\s*[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+\S+.*\b(curl|wget|sh|bash|python|nc|/tmp/)", re.I | re.M)
_LAUNCHD = re.compile(r"<key>\s*RunAtLoad\s*</key>|<key>\s*ProgramArguments\s*</key>", re.I)


def _persistence_payloads(code: str, out: list):
    lines = code.splitlines()
    def lineno(m):
        return code[:m.start()].count("\n") + 1
    for rx, msg in ((_AUTOSTART, "XDG autostart .desktop entry with Exec= (login persistence)"),
                    (_SYSTEMD, "systemd service unit with ExecStart= (service persistence)"),
                    (_LAUNCHD, "launchd plist with RunAtLoad/ProgramArguments (macOS persistence)")):
        m = rx.search(code)
        if m:
            out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.62, lineno(m), "uni.persist.payload", msg))
    m = _CRONLINE.search(code)
    if m:
        out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.6, lineno(m), "uni.persist.cronline",
                           "cron schedule line invoking a command (scheduled-task persistence)"))


def analyze(code: str, analysis: Analysis) -> None:
    out: list[Finding] = []
    _prompt_injection(code, out)
    _secrets(code, out)
    _network_refs(code, out)
    _persistence_payloads(code, out)
    analysis.findings.extend(out)
    for f in out:
        if f.category == AI_TARGETED_INSTRUCTIONS:
            analysis.signals["prompt.injection_phrase"] = max(analysis.signals.get("prompt.injection_phrase", 0), f.score)
        elif f.rule.startswith("uni.secret"):
            analysis.signals["secret.hardcoded"] = max(analysis.signals.get("secret.hardcoded", 0), f.score)
