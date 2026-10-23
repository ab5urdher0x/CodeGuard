"""Canonical fact model shared by every analyzer.

Analyzers never decide verdicts. They emit Findings in this one vocabulary and
the aggregator scores them, so adding a language means adding an analyzer only.
"""
from dataclasses import dataclass, field

SECRET_ACCESS = "secret_access"
DATA_EXFILTRATION = "data_exfiltration"
DESTRUCTIVE_COMMAND = "destructive_command"
PERSISTENCE_OR_PRIVESC = "persistence_or_privesc"
OBFUSCATED_EXECUTION = "obfuscated_execution"
DEPENDENCY_RISK = "dependency_risk"
RESOURCE_EXHAUSTION = "resource_exhaustion"
SSRF_NETWORK_EXFIL = "ssrf_network_exfil"
AI_TARGETED_INSTRUCTIONS = "ai_targeted_instructions"

CATEGORIES = (
    SECRET_ACCESS, DATA_EXFILTRATION, DESTRUCTIVE_COMMAND, PERSISTENCE_OR_PRIVESC,
    OBFUSCATED_EXECUTION, DEPENDENCY_RISK, RESOURCE_EXHAUSTION, SSRF_NETWORK_EXFIL,
    AI_TARGETED_INSTRUCTIONS,
)

# Our two extra categories. Reported in `sub_categories`, each mapped onto the
# official parent category in `categories` so official scoring is unaffected.
CODE_INJECTION = "code_injection"
INSECURE_DESERIALIZATION = "insecure_deserialization"
SUB_CATEGORIES = (CODE_INJECTION, INSECURE_DESERIALIZATION)


@dataclass
class Finding:
    category: str
    score: float          # confidence this finding is a real threat, 0..1
    line: int | None
    rule: str             # stable rule id, e.g. "py.exec.decoded"
    message: str
    sub_category: str | None = None
    intel: str | None = None  # threat-intel tag, e.g. "black_october:litellm-1.107.0"

    def __post_init__(self):
        assert self.category in CATEGORIES, self.category
        self.score = max(0.0, min(1.0, float(self.score)))


@dataclass
class Analysis:
    language: str
    language_confidence: float
    findings: list[Finding] = field(default_factory=list)
    parse_ok: bool = True
    # Named numeric signals for the ML feature vector (names registered in engine/features.py).
    signals: dict[str, float] = field(default_factory=dict)
