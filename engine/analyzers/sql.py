"""SQL analyzer: statement-level rules. Flags destructive statements without a
WHERE guard, privilege grants, and injectable string concatenation. Comment-based
prompt injection and lookalike hosts are handled by the universal pass.
"""
import re

from engine.facts import (
    DATA_EXFILTRATION, DESTRUCTIVE_COMMAND, PERSISTENCE_OR_PRIVESC, Analysis, Finding,
)

# strip string/line/block comments and literals so verbs inside them don't fire
_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_STRING = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"")


def _statements(code: str):
    clean = _BLOCK_COMMENT.sub(" ", code)
    clean = _LINE_COMMENT.sub(" ", clean)
    # keep line numbers: split on ; but track offsets
    pos, line = 0, 1
    buf_start = 1
    buf = []
    for ch in clean:
        if ch == "\n":
            line += 1
        if ch == ";":
            yield "".join(buf), buf_start
            buf, buf_start = [], line
        else:
            if not buf:
                buf_start = line
            buf.append(ch)
    if "".join(buf).strip():
        yield "".join(buf), buf_start


_DANGER_FUNC = re.compile(r"\b(xp_cmdshell|sys_exec|load_file|into\s+outfile|into\s+dumpfile|pg_read_file|"
                          r"dbms_scheduler|utl_http|lo_import|lo_export)\b", re.I)


def analyze(code: str, analysis: Analysis) -> None:
    out: list[Finding] = []
    for stmt, line in _statements(code):
        s = stmt.strip()
        if not s:
            continue
        no_str = _STRING.sub("''", s)          # literals blanked for structural checks
        verb_m = re.match(r"\s*([A-Za-z]+)", no_str)
        verb = verb_m.group(1).upper() if verb_m else ""
        up = no_str.upper()
        has_where = bool(re.search(r"\bWHERE\b", up))
        has_concat = "||" in no_str or re.search(r"\+\s*@|\bCONCAT\s*\(", up) or "%s" in s or "{}" in s or "{0" in s

        if verb in ("DROP", "TRUNCATE"):
            obj = re.search(r"\b(TABLE|DATABASE|SCHEMA)\b", up)
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.88, line, "sql.drop",
                               f"{verb} {obj.group(1) if obj else ''} destroys data/schema"))
        elif verb == "DELETE" and not has_where:
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.85, line, "sql.delete.nowhere", "DELETE with no WHERE clause removes all rows"))
        elif verb == "UPDATE" and not has_where:
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.82, line, "sql.update.nowhere", "UPDATE with no WHERE clause rewrites every row"))
        elif verb in ("DELETE", "UPDATE") and has_concat:
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.72, line, "sql.injection.destructive",
                               f"{verb} built by string concatenation (injectable, can destroy data)"))
        elif verb in ("SELECT", "INSERT") and has_concat and re.search(r"WHERE|VALUES", up):
            out.append(Finding(DATA_EXFILTRATION, 0.6, line, "sql.injection.read",
                               f"{verb} built by string concatenation (injectable)"))

        if verb == "GRANT" and re.search(r"\b(ALL|SUPER|ALL\s+PRIVILEGES|GRANT\s+OPTION)\b", up):
            out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.75, line, "sql.grant", "grants elevated database privileges"))
        if re.search(r"\bCREATE\s+(OR\s+REPLACE\s+)?(USER|ROLE)\b", up) or re.search(r"\bALTER\s+USER\b.*\bSUPERUSER\b", up):
            out.append(Finding(PERSISTENCE_OR_PRIVESC, 0.6, line, "sql.user", "creates/elevates a database account"))
        if _DANGER_FUNC.search(s):
            out.append(Finding(DESTRUCTIVE_COMMAND, 0.85, line, "sql.danger_func",
                               "uses a SQL function that reaches the OS/filesystem (RCE/exfil)"))

    analysis.findings.extend(out)
    for f in out:
        if "nowhere" in f.rule or "injection" in f.rule:
            analysis.signals["sql.no_where" if "nowhere" in f.rule else "sql.formatted"] = max(
                analysis.signals.get("sql.no_where" if "nowhere" in f.rule else "sql.formatted", 0), f.score)
