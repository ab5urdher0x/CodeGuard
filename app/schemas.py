"""Request/response models. The six PS fields are fixed; extras can be stripped with CODEGUARD_STRICT_SCHEMA=1."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    code: str = Field(..., max_length=1_000_000)


class FindingOut(BaseModel):
    category: str
    score: float
    line: int | None = None
    rule: str
    message: str
    sub_category: str | None = None
    intel: str | None = None


class EvaluateResponse(BaseModel):
    verdict: Literal["allow", "block"]
    risk_score: float = Field(..., ge=0.0, le=1.0)
    categories: list[str]
    code_language: str
    reason: str
    vulnerable_lines: list[int]
    # optional extras (not part of the fixed schema)
    sub_categories: list[str] | None = None
    findings: list[FindingOut] | None = None
    latency_ms: float | None = None
    neural_used: bool | None = None
