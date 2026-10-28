"""Module 5 - Explainable risk assessment.

Three transparent scoring approaches are implemented so they can be compared
on the labelled dataset (see module7_evaluation.py):

    severity_sum   every finding adds points by severity only
    rule_weighted  every rule has its own weight, scaled by finding severity
    max_severity   category = most severe finding, escalated when several
                   independent medium findings agree

The weights and thresholds below are *initial hypotheses*, not facts.  The
resulting score is an ordinal indicator for triage; it is NOT a calibrated
probability that a message is malicious.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from module4_spoofing_detection import SEVERITY_ORDER, Finding

APPROACHES = ("severity_sum", "rule_weighted", "max_severity")

SEVERITY_POINTS = {"info": 0.0, "low": 1.0, "medium": 3.0, "high": 6.0}
SEVERITY_FACTOR = {"info": 0.0, "low": 0.4, "medium": 0.75, "high": 1.0}

RULE_WEIGHTS: Dict[str, float] = {
    "AUTH-DMARC-FAIL": 4.0,
    "AUTH-SPF-FAIL": 2.0,
    "AUTH-DKIM-FAIL": 2.0,
    "AUTH-NOT-ALIGNED": 3.0,
    "AUTH-MISSING": 1.0,
    "AUTH-UNTRUSTED-CLAIMS": 3.0,
    "SENDER-REPLYTO-MISMATCH": 2.0,
    "SENDER-RETURNPATH-MISMATCH": 0.5,
    "SENDER-DISPLAYNAME-ADDRESS": 4.0,
    "SENDER-DISPLAYNAME-BRAND": 3.0,
    "DOMAIN-LOOKALIKE": 5.0,
    "DOMAIN-INTERNAL-LOOKALIKE": 5.0,
    "HEADER-DUPLICATE": 3.0,
    "HEADER-MISSING": 1.0,
    "HEADER-MALFORMED": 1.0,
    "ROUTE-INCONSISTENT": 2.0,
    "ROUTE-MISSING": 1.0,
    "MSGID-DOMAIN-MISMATCH": 0.5,
    "CONTEXT-MAILING-LIST": 0.0,
    "CONTEXT-FORWARDED": 0.0,
}

# (medium threshold, high threshold) for the additive approaches.
THRESHOLDS = {
    "severity_sum": (3.0, 6.0),
    "rule_weighted": (2.5, 5.0),
}

DISCLAIMER = ("The score ranks how many and how serious the header indicators are. "
              "It is not a calibrated probability of maliciousness, and a low score "
              "does not prove a message is safe (e.g. a compromised legitimate account "
              "passes every header check).")


@dataclass
class Contribution:
    rule_id: str
    title: str
    severity: str
    points: float
    explanation: str


@dataclass
class RiskAssessment:
    approach: str
    score: float
    category: str  # low | medium | high
    flagged: bool  # category >= medium; used for evaluation
    thresholds: Optional[List[float]]
    contributions: List[Contribution]
    confidence_notes: List[str] = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict:
        return asdict(self)


def _category(score: float, thresholds) -> str:
    medium, high = thresholds
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    return "low"


def _confidence_notes(findings: List[Finding]) -> List[str]:
    ids = {f.rule_id for f in findings}
    notes = []
    if "AUTH-MISSING" in ids:
        notes.append("No trusted authentication results: sender identity is largely unverified.")
    if "ROUTE-MISSING" in ids:
        notes.append("No delivery route: origin of the message cannot be assessed.")
    if "HEADER-MISSING" in ids or "HEADER-MALFORMED" in ids:
        notes.append("Missing or malformed fields limit what could be checked.")
    if "CONTEXT-MAILING-LIST" in ids or "CONTEXT-FORWARDED" in ids:
        notes.append("Message was relayed (list/forwarder); some failures are expected "
                     "and were down-weighted.")
    return notes


def assess_risk(findings: List[Finding], approach: str = "severity_sum",
                thresholds: Optional[tuple] = None) -> RiskAssessment:
    if approach not in APPROACHES:
        raise ValueError(f"Unknown scoring approach {approach!r}; choose from {APPROACHES}.")
    contributions: List[Contribution] = []

    if approach == "max_severity":
        relevant = [f for f in findings if not f.rule_id.startswith("CONTEXT-")]
        top = max((SEVERITY_ORDER[f.severity] for f in relevant), default=0)
        medium_categories = {f.category for f in relevant if f.severity == "medium"}
        category = {0: "low", 1: "low", 2: "medium", 3: "high"}[top]
        escalated = category == "medium" and len(medium_categories) >= 2
        if escalated:
            category = "high"
        for f in relevant:
            if f.severity in ("medium", "high"):
                contributions.append(Contribution(
                    f.rule_id, f.title, f.severity, float(SEVERITY_ORDER[f.severity]),
                    "Most severe finding sets the category"
                    + ("; two or more independent medium findings escalate to high."
                       if escalated else ".")))
        return RiskAssessment(approach, float(top), category, category != "low", None,
                              contributions, _confidence_notes(findings))

    total = 0.0
    for f in findings:
        if approach == "severity_sum":
            points = SEVERITY_POINTS[f.severity]
            why = f"{f.severity} severity = {points:g} point(s)"
        else:
            weight = RULE_WEIGHTS.get(f.rule_id, 1.0)
            points = round(weight * SEVERITY_FACTOR[f.severity], 2)
            why = (f"rule weight {weight:g} x {f.severity} factor "
                   f"{SEVERITY_FACTOR[f.severity]:g}")
        if points:
            contributions.append(Contribution(f.rule_id, f.title, f.severity, points, why))
        total += points
    total = round(total, 2)
    limits = thresholds or THRESHOLDS[approach]
    category = _category(total, limits)
    contributions.sort(key=lambda c: -c.points)
    return RiskAssessment(approach, total, category, category != "low", list(limits),
                          contributions, _confidence_notes(findings))
