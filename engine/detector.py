"""Heuristic language detection: shebang -> parser confirmation -> weighted cues."""
import ast
import re

LANGUAGES = ("python", "bash", "javascript", "sql", "yaml", "markdown")

_SHEBANGS = {
    "python": re.compile(r"^#!.*\bpython[\d.]*\b"),
    "bash": re.compile(r"^#!.*\b(ba|z|da|k)?sh\b"),
    "javascript": re.compile(r"^#!.*\b(node|deno|bun)\b"),
}

_CUES: dict[str, list[tuple[str, float]]] = {
    "python": [
        (r"^\s*(from\s+[\w.]+\s+)?import\s+\w+", 3), (r"^\s*def\s+\w+\s*\(.*\)\s*(->.*)?:", 3),
        (r"^\s*class\s+\w+.*:\s*$", 2), (r"\bself\.", 1.5), (r"^\s*if __name__\s*==", 3),
        (r"\b(elif|None|True|False|lambda)\b", 1), (r"^\s*@\w+", 0.5), (r"\bprint\(", 0.5),
    ],
    "javascript": [
        (r"\b(const|let|var)\s+\w+\s*=", 2.5), (r"\bfunction\s*\w*\s*\(", 2), (r"=>", 1.5),
        (r"\brequire\(['\"]", 3), (r"^\s*import .* from ['\"]", 3), (r"\bmodule\.exports\b", 3),
        (r"\bconsole\.log\(", 2), (r"\b(await|async)\b", 0.5), (r"\bprocess\.env\b", 2), (r";\s*$", 0.3),
        (r"\b(fs|child_process|process|require|exports|document|window|navigator|axios)\b", 1.5),
        (r"\.\w+Sync\s*\(", 1.5), (r"\bnew\s+[A-Z]\w*\(", 0.5), (r"`[^`]*\$\{", 1),
    ],
    "bash": [
        (r"^\s*(sudo|apt(-get)?|yum|curl|wget|chmod|chown|rm|mkdir|cd|echo|export|cat|grep|sed|awk|dd|systemctl|crontab|nc|ssh|scp|tar|pip3?|npm|yarn)\b", 1.5),
        (r"\$\{?\w+\}?", 0.7), (r"^\s*(if|while|for)\b.*;\s*(then|do)\b", 3), (r"^\s*(fi|done|esac)\s*$", 3),
        (r"\s\|\s*\w+", 0.8), (r"\s&&\s", 1), (r"\s-{1,2}[a-zA-Z][\w-]*", 0.3), (r">\s*/dev/", 1.5),
    ],
    "sql": [
        (r"^\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE|BEGIN|COMMIT|WITH)\b", 3),
        (r"\b(FROM|WHERE|JOIN|GROUP BY|ORDER BY|VALUES|SET)\b", 1.5), (r";\s*$", 0.5), (r"--\s", 0.5),
    ],
    "yaml": [
        (r"^\s*[\w.-]+:\s*(\S.*)?$", 1), (r"^\s*-\s+[\w.-]+:\s", 1.5), (r"^---\s*$", 2),
        (r"^\s*(on|jobs|steps|runs-on|uses|run|name|services|image|apiVersion|kind|metadata|spec):", 2),
    ],
    "markdown": [
        (r"^#{1,6}\s+\S", 2.5), (r"^\s*[-*]\s+\S", 0.7), (r"^```", 3), (r"\[[^\]]+\]\([^)]+\)", 2), (r"\*\*[^*]+\*\*", 1.5),
    ],
}
_COMPILED = {lang: [(re.compile(p, re.M | (re.I if lang == "sql" else 0)), w) for p, w in cues] for lang, cues in _CUES.items()}


def _python_structure(code: str) -> float:
    """0 = not Python; 0.5 = parses but trivial (could be shell too, e.g. 'ls -la');
    1 = parses with real Python structure (calls with args, imports, defs)."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return 0.0
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Attribute, ast.keyword, ast.Assign, ast.With, ast.For, ast.While)):
            return 1.0
        if isinstance(node, ast.Call) and (node.args or node.keywords):
            return 1.0
    return 0.5




def detect_language(code: str) -> tuple[str, float]:
    """Return (language, confidence in 0..1)."""
    stripped = code.lstrip()
    first = stripped.splitlines()[0] if stripped else ""
    for lang, rx in _SHEBANGS.items():
        if rx.match(first):
            return lang, 0.99

    scores = {lang: 0.0 for lang in LANGUAGES}
    for lang, cues in _COMPILED.items():
        for rx, w in cues:
            hits = len(rx.findall(code))
            scores[lang] += w * min(hits, 5)

    # Parser confirmation: a clean Python parse is strong evidence only if Python cues exist
    # (single bash words like `ls` are also valid Python expressions).
    pystruct = _python_structure(code)
    other_best = max(v for k, v in scores.items() if k != "python")
    if scores["python"] > 0 and pystruct:
        scores["python"] *= 2.0
    if pystruct >= 1.0:
        # Valid Python with real structure (assignment / call-with-args / def / import).
        # SQL keywords / markdown '#' headers / yaml keys usually LEAK from comments and
        # string literals, while real SQL/markdown/yaml do not parse as Python with structure.
        # So outrank those; genuine JS/bash *code* cues (writeFileSync, require(, shebang) are
        # strong (>=3) and real, so defer to them.
        js_bash = max(scores["javascript"], scores["bash"])
        leak = max(scores["sql"], scores["yaml"], scores["markdown"])
        boost = max(leak + 2.0, 5.0) if js_bash < 3 else scores["python"]
        scores["python"] = max(scores["python"], boost)
    # SQL needs a real statement verb; a bare ';' or '--' must not make it SQL.
    if not _COMPILED["sql"][0][0].search(code):
        scores["sql"] *= 0.15
    # Markdown/YAML cues are weak in code files; demote them when real code cues dominate.
    code_best = max(scores["python"], scores["javascript"], scores["bash"], scores["sql"])
    if code_best > 6:
        scores["yaml"] *= 0.4
        scores["markdown"] *= 0.5

    lang = max(scores, key=scores.get)
    total = sum(scores.values()) or 1.0
    if scores[lang] == 0:
        return "bash", 0.2  # one-liners without cues are most often shell commands
    return lang, round(scores[lang] / total, 3)
