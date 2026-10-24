from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SAMPLE = "import os\nprint(os.getcwd())\n"


def _check(r):
    assert r["verdict"] in ("allow", "block")
    assert isinstance(r["risk_score"], (int, float)) and 0.0 <= r["risk_score"] <= 1.0
    assert isinstance(r["categories"], list) and all(isinstance(c, str) for c in r["categories"])
    assert isinstance(r["code_language"], str)
    assert isinstance(r["reason"], str)
    assert isinstance(r["vulnerable_lines"], list) and all(isinstance(x, int) for x in r["vulnerable_lines"])


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_evaluate_simple():
    r = client.post("/evaluate", json={"code": SAMPLE})
    assert r.status_code == 200
    _check(r.json())


def test_evaluate_empty():
    r = client.post("/evaluate", json={"code": ""})
    assert r.status_code == 200
    _check(r.json())


def test_evaluate_300kb():
    code = "x = 1  # filler line\n" * (300 * 1024 // 21 + 1)
    assert len(code) >= 300 * 1024
    r = client.post("/evaluate", json={"code": code})
    assert r.status_code == 200
    _check(r.json())


def test_batch():
    r = client.post("/evaluate/batch", json=[{"code": SAMPLE}, {"code": ""}, {"code": "echo hi\n"}])
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 3
    for x in body:
        _check(x)


def test_oversized_input_not_a_truncation_bypass():
    # pad-and-append must not evade: payload hidden after >256KB padding must still block
    from engine.pipeline import evaluate
    pad = "# benign comment line\n" * 15000  # ~330 KB
    r = evaluate(pad + 'import os\nos.system("rm -rf /")\n')
    assert r["verdict"] == "block"
