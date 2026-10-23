import importlib.util
import os

_p = os.path.join(os.path.dirname(__file__), "..", "eval", "evaluate.py")
_s = importlib.util.spec_from_file_location("cg_evaluate", _p)
ev = importlib.util.module_from_spec(_s)
_s.loader.exec_module(ev)


def test_normalize_dev_format():
    assert ev.normalize_row({"label": 0, "category": "benign"}) == (False, set())
    assert ev.normalize_row({"label": 1, "category": "secret_access, dependency_risk"}) == (
        True, {"secret_access", "dependency_risk"})


def test_normalize_our_format():
    labels = [0] * 9
    labels[2] = 1
    labels[8] = 1
    row = {"label": 1, "categories": ["destructive_command", "ai_targeted_instructions"], "labels": labels}
    assert ev.normalize_row(row) == (True, {"destructive_command", "ai_targeted_instructions"})
    assert ev.normalize_row({"label": 0, "categories": [], "labels": [0] * 9}) == (False, set())
    assert ev.normalize_row({"label": 1, "categories": ["secret_access"]}) == (True, {"secret_access"})


def test_validate_response():
    ok = {"verdict": "allow", "risk_score": 0.1, "categories": [], "code_language": "python"}
    assert ev.validate_response(ok) == []
    assert ev.validate_response({**ok, "reason": "x", "vulnerable_lines": [1, 2]}) == []
    assert ev.validate_response({**ok, "verdict": "maybe"})
    assert ev.validate_response({**ok, "risk_score": 1.5})
    assert ev.validate_response({**ok, "categories": "x"})
    assert ev.validate_response({**ok, "vulnerable_lines": ["1"]})
    assert ev.validate_response({"verdict": "block"})


def test_metric_math():
    rows = [
        {"id": "a", "code": "1", "label": 1, "category": "secret_access", "language": "python"},
        {"id": "b", "code": "2", "label": 1, "category": "secret_access", "language": "python"},
        {"id": "c", "code": "3", "label": 0, "category": "benign", "language": "bash"},
        {"id": "d", "code": "4", "label": 0, "category": "benign", "language": "bash"},
    ]
    answers = {
        "1": {"verdict": "block", "risk_score": 0.9, "categories": ["secret_access"], "code_language": "python", "latency_ms": 1.0},
        "2": {"verdict": "allow", "risk_score": 0.1, "categories": [], "code_language": "python", "latency_ms": 3.0},
        "3": {"verdict": "block", "risk_score": 0.8, "categories": ["secret_access"], "code_language": "bash", "latency_ms": 2.0},
        "4": {"verdict": "allow", "risk_score": 0.0, "categories": [], "code_language": "bash", "latency_ms": 4.0},
    }
    items, fails = ev.run(rows, lambda code: answers[code])
    assert fails == []
    m = ev.compute(items)
    v = m["verdict"]
    assert (v["tp"], v["fp"], v["tn"], v["fn"]) == (1, 1, 1, 1)
    assert v["precision"] == 0.5 and v["recall"] == 0.5 and v["f1"] == 0.5
    assert v["fpr"] == 0.5 and v["accuracy"] == 0.5
    sa = m["categories"]["secret_access"]
    assert (sa["tp"], sa["fp"], sa["fn"]) == (1, 1, 1)  # FP on negative row counted
    assert m["exact"] == 0.5 and m["n_pos"] == 2
    assert m["languages"]["bash"]["fp"] == 1 and m["languages"]["python"]["fn"] == 1
    assert m["latency"]["max"] == 4.0 and m["latency"]["p50"] == 2.5
    assert sorted(k for k, _ in ev.misses(items)) == ["FN", "FP"]
    assert "Misses" in ev.render_markdown(m, fails, items)


def test_schema_failure_counted():
    rows = [{"id": "x", "code": "z", "label": 1, "category": "secret_access"}]
    _, fails = ev.run(rows, lambda c: {"verdict": "block", "risk_score": 7, "categories": [], "code_language": "x"})
    assert len(fails) == 1 and fails[0][0] == "x"
    items, fails = ev.run(rows, lambda c: 1 / 0)
    assert len(fails) == 1 and items[0]["pred_pos"] is False


def test_category_mismatch_listed():
    rows = [{"id": "m", "code": "z", "label": 1, "category": "secret_access"}]
    resp = {"verdict": "block", "risk_score": 0.9, "categories": ["dependency_risk"], "code_language": "python"}
    items, _ = ev.run(rows, lambda c: resp)
    assert [k for k, _ in ev.misses(items)] == ["CAT"]
