"""YAML / Markdown analyzer.

These formats mostly carry risk through (a) prompt injection in comments — handled
by the universal pass — and (b) embedded commands/code. Here we run CI `run:`
steps through the shell analyzer and Markdown fenced code blocks through the
matching language analyzer.
"""
import re

from engine.analyzers import shell
from engine.facts import DEPENDENCY_RISK, OBFUSCATED_EXECUTION, Analysis, Finding

_RUN_RX = re.compile(r"^\s*(?:-\s*)?run:\s*(?:[|>][-+]?\s*)?(.*)$")
_CURL_PIPE = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I)
_FENCE = re.compile(r"^```(\w+)?\s*$")


def _analyze_shell_lines(lines, out, base_line=0):
    for off, ln in enumerate(lines):
        m = _RUN_RX.match(ln)
        cmd = m.group(1).strip() if m else None
        if cmd:
            for f in shell.analyze_command(cmd, base_line + off + 1, origin="ci"):
                out.append(f)


def analyze(code: str, analysis: Analysis) -> None:
    out: list[Finding] = []
    lines = code.splitlines()

    # CI run: steps (inline and the first line of block scalars)
    _analyze_shell_lines(lines, out)

    # curl | sh anywhere in the document
    for i, ln in enumerate(lines, 1):
        if _CURL_PIPE.search(ln):
            out.append(Finding(OBFUSCATED_EXECUTION, 0.82, i, "ci.curl_pipe_sh",
                               "pipes downloaded content directly into a shell"))

    # Markdown fenced code blocks -> dispatch to the matching analyzer
    i = 0
    while i < len(lines):
        fm = _FENCE.match(lines[i])
        if fm:
            lang = (fm.group(1) or "").lower()
            start = i + 1
            j = start
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            block = "\n".join(lines[start:j])
            if block.strip():
                _dispatch_block(lang, block, start, out, analysis)
            i = j + 1
        else:
            i += 1

    analysis.findings.extend(out)


def _dispatch_block(lang, block, start_line, out, analysis):
    from engine.analyzers import javascript, python_ast, sql
    sub = Analysis(language=lang or "text", language_confidence=0.5)
    try:
        if lang in ("python", "py"):
            python_ast.analyze(block, sub)
        elif lang in ("js", "javascript", "ts", "typescript", "node"):
            javascript.analyze(block, sub)
        elif lang == "sql":
            sql.analyze(block, sub)
        elif lang in ("bash", "sh", "shell", "console", ""):
            sub.findings.extend(shell.analyze_bash(block))
    except Exception:
        return
    # re-line findings to the document and keep them
    for f in sub.findings:
        f.line = (f.line or 1) + start_line
        out.append(f)
