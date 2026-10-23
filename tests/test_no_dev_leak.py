"""Compliance guard: our own code and generated data must not copy distinctive
content from the public dev sample. Protects the PS floor 'no hard-coded answers
/ patterns copied verbatim from public datasets'."""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEV = os.path.join(ROOT, "data", "dev", "codeguard_dev.jsonl")


def _dev_comment_prose():
    """Distinctive dev lines: comments/prose, which are the real copy risk."""
    out = set()
    cmt = re.compile(r"^\s*(#|//|<!--|--\s)")
    for ln in open(DEV):
        for row in json.loads(ln)["code"].splitlines():
            s = row.strip()
            if len(s) >= 20 and (cmt.match(row) or (s[:1].isalpha() and " " in s and "(" not in s and "=" not in s)):
                out.add(s)
    return out


def _scan_dir(path):
    texts = []
    for base, _, files in os.walk(path):
        if "__pycache__" in base:
            continue
        for f in files:
            if f.endswith((".py", ".json", ".jsonl", ".md", ".txt")):
                try:
                    texts.append(open(os.path.join(base, f)).read())
                except Exception:
                    pass
    return "\n".join(texts)


def test_engine_and_generator_do_not_embed_dev_prose():
    distinctive = _dev_comment_prose()
    assert distinctive, "expected some distinctive dev lines to check against"
    corpus = _scan_dir(os.path.join(ROOT, "engine")) + _scan_dir(os.path.join(ROOT, "data", "gen"))
    leaked = [s for s in distinctive if s in corpus]
    assert not leaked, f"dev content copied into engine/generator: {leaked[:3]}"


def test_generated_dataset_has_no_dev_comment_leak():
    syn = os.path.join(ROOT, "data", "synthetic")
    if not os.path.isdir(syn):
        return  # dataset not generated in this checkout; generator self-checks at build time
    distinctive = _dev_comment_prose()
    cmt = re.compile(r"^\s*(#|//|<!--|--\s)")
    for name in os.listdir(syn):
        if not name.endswith(".jsonl"):
            continue
        for ln in open(os.path.join(syn, name)):
            for row in json.loads(ln)["code"].splitlines():
                s = row.strip()
                if cmt.match(row) and s in distinctive:
                    raise AssertionError(f"dev comment leaked into {name}: {s!r}")
