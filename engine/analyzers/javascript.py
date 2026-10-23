"""JavaScript/TypeScript analyzer: structural regex (no JS parser in stdlib).

Covers code execution (eval/Function/vm), shell (child_process), network to
risky hosts, filesystem persistence, obvious deserialization and dependency
installs. Hardcoded secrets, prompt injection and SSRF host classification come
from the universal pass; this adds JS-specific call shapes.
"""
import re

from engine import knowledge as K
from engine.analyzers import shell
from engine.facts import (
    DATA_EXFILTRATION, DEPENDENCY_RISK, DESTRUCTIVE_COMMAND, OBFUSCATED_EXECUTION,
    PERSISTENCE_OR_PRIVESC, SSRF_NETWORK_EXFIL, Analysis, Finding,
)

_STR = r"""['"`]([^'"`]*)['"`]"""

_RULES = [
    (re.compile(r"\beval\s*\("), OBFUSCATED_EXECUTION, 0.8, "js.eval", "eval() executes a runtime string"),
    (re.compile(r"\bnew\s+Function\s*\("), OBFUSCATED_EXECUTION, 0.78, "js.function_ctor", "new Function() builds code at runtime"),
    (re.compile(r"\bvm\.(runInThisContext|runInNewContext|compileFunction)\b"), OBFUSCATED_EXECUTION, 0.75, "js.vm", "vm module runs dynamic code"),
    (re.compile(r"\brequire\s*\(\s*[^'\"`)]+[)+]"), OBFUSCATED_EXECUTION, 0.6, "js.require.dynamic", "dynamic require() of a computed module name"),
    (re.compile(r"\bBuffer\.from\s*\([^)]*,\s*['\"]base64['\"]\s*\)"), OBFUSCATED_EXECUTION, 0.45, "js.base64", "base64 decode (check for exec sink)"),
]

_SHELL_CALL = re.compile(r"\bchild_process\.(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(.+)")
_EXEC_SHORT = re.compile(r"\b(exec|execSync|spawnSync)\s*\(\s*(.+)")
_FETCH = re.compile(r"\b(fetch|axios\.(get|post|put)|axios|http\.request|https\.request|got|superagent\.\w+)\s*\(\s*" + _STR)
_FS_WRITE = re.compile(r"\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(\s*" + _STR)
_FS_DANGER = re.compile(r"\bfs\.(rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\(\s*" + _STR + r"[^)]*\{\s*[^}]*recursive")
_INSTALL = re.compile(r"\b(npm\s+(install|i)|yarn\s+add|pnpm\s+add)\b([^\n'\"`;]*)", re.I)
_DESERIALIZE = re.compile(r"\b(node-serialize|serialize-javascript)\b|\bunserialize\s*\(")


def _first_str(text: str):
    m = re.search(_STR, text)
    return m.group(1) if m else None


def analyze(code: str, analysis: Analysis) -> None:
    out: list[Finding] = []
    for i, line in enumerate(code.splitlines(), 1):
        for rx, cat, sev, rule, msg in _RULES:
            if rx.search(line):
                out.append(Finding(cat, sev, i, rule, msg))

        m = _SHELL_CALL.search(line) or _EXEC_SHORT.search(line)
        if m:
            rest = m.group(2)
            cmd = _first_str(rest)
            dynamic = cmd is None or "`" in rest or "+" in rest.split("//")[0] or "${" in rest
            if cmd and "${" not in cmd and "+" not in rest.split(")")[0]:
                for f in shell.analyze_command(cmd, i, origin="js"):
                    out.append(f)
            if dynamic:
                out.append(Finding(DESTRUCTIVE_COMMAND, 0.78, i, "js.child_process.injection",
                                   "shell command built from runtime values (command injection)"))

        for fm in _FETCH.finditer(line):
            url = fm.group(fm.lastindex)
            risk, host = K.classify_url(url)
            if risk == "metadata":
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.85, i, "js.ssrf.metadata", f"request to cloud metadata endpoint {host}",
                                   intel="black_october:imds" if "169.254" in url else None))
            elif risk in ("internal", "loopback"):
                out.append(Finding(SSRF_NETWORK_EXFIL, 0.6, i, "js.ssrf.internal", f"request to internal host {host}"))
            elif risk == "lookalike":
                out.append(Finding(DATA_EXFILTRATION, 0.7, i, "js.exfil.lookalike", f"request to lookalike domain {host}",
                                   intel="black_october:lookalike"))
            elif risk == "exfil_dest":
                out.append(Finding(DATA_EXFILTRATION, 0.65, i, "js.exfil.dest", f"request to suspicious host {host}"))

        fw = _FS_WRITE.search(line)
        if fw and (pt := K.persistence_target(fw.group(2))):
            sev = 0.9 if K.is_startup_hook(fw.group(2)) else 0.8
            out.append(Finding(PERSISTENCE_OR_PRIVESC, sev, i, "js.persist.write", f"writes to persistence location {pt}"))
        if _FS_DANGER.search(line):
            tgt = _first_str(line)
            if tgt and K.is_dangerous_delete_target(tgt):
                out.append(Finding(DESTRUCTIVE_COMMAND, 0.85, i, "js.fs.rmrf", f"recursive delete of critical path {tgt}"))
            else:
                out.append(Finding(DESTRUCTIVE_COMMAND, 0.5, i, "js.fs.rm", "recursive filesystem delete"))

        inst = _INSTALL.search(line)
        if inst:
            toks = ("npm install " + inst.group(3)).split()
            out.extend(shell.analyze_install(toks[:2] + [t for t in toks[2:] if t], i, origin="js"))
        if _DESERIALIZE.search(line):
            out.append(Finding(OBFUSCATED_EXECUTION, 0.7, i, "js.deserialize", "insecure deserialization (node-serialize/unserialize)"))

    analysis.findings.extend(out)
