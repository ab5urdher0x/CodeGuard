"""CodeGuard HTTP API. Person B owns this file (UI page, batch tuning, deployment)."""
import logging
import os

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.schemas import EvaluateRequest, EvaluateResponse
from engine.pipeline import evaluate

log = logging.getLogger("codeguard")
STRICT = os.getenv("CODEGUARD_STRICT_SCHEMA") == "1"
_REQUIRED = ("verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines")

app = FastAPI(title="CodeGuard", version="0.1.0")
_INDEX = Path(__file__).parent / "static" / "index.html"


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(_INDEX, media_type="text/html")


def _safe_evaluate(code: str) -> dict:
    try:
        resp = evaluate(code)
    except Exception:  # fail closed, but always with a valid schema
        log.exception("evaluate failed")
        resp = {"verdict": "block", "risk_score": 1.0, "categories": [], "code_language": "unknown",
                "reason": "Blocked: internal analysis error (fail-closed policy)", "vulnerable_lines": []}
    return {k: resp[k] for k in _REQUIRED} if STRICT else resp


@app.post("/evaluate", response_model=EvaluateResponse, response_model_exclude_none=True)
def evaluate_one(req: EvaluateRequest):
    return _safe_evaluate(req.code)


@app.post("/evaluate/batch", response_model=list[EvaluateResponse], response_model_exclude_none=True)
def evaluate_batch(reqs: list[EvaluateRequest]):
    return [_safe_evaluate(r.code) for r in reqs]


@app.get("/health")
def health():
    return {"status": "ok"}
