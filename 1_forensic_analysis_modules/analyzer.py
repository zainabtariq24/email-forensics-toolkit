"""Pipeline: runs Modules 1-5 on raw bytes and returns one JSON-serialisable result.

AnalysisSettings are recorded with every case so results are reproducible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from module1_header_extraction import parse_email, sanitize_for_display
from module2_route_reconstruction import analyze_route
from module3_authentication import analyze_authentication
from module4_spoofing_detection import PROTECTED_DOMAINS, detect_findings
from module5_risk_assessment import assess_risk
from module6_forensic_report import TOOL_NAME, __version__, new_case_id, sha256_hex

# Selected by module7_evaluation.py: best F1 on the tuning split (tied with
# max_severity; severity_sum is listed first and gives a finer-grained score).
DEFAULT_SCORING_APPROACH = "severity_sum"


@dataclass
class AnalysisSettings:
    # Empty = auto: trust the receiving server's own authserv-id / domain.
    trusted_authserv_ids: List[str] = field(default_factory=list)
    trusted_domains: List[str] = field(default_factory=list)
    # Extra domains to protect against look-alikes (e.g. your organisation).
    protected_domains: List[str] = field(default_factory=list)
    dns_lookups: bool = False
    scoring_approach: str = DEFAULT_SCORING_APPROACH
    clock_skew_minutes: int = 5

    def all_protected_domains(self) -> List[str]:
        extra = [d.lower().strip() for d in self.protected_domains + self.trusted_domains
                 if d.strip()]
        return list(dict.fromkeys(list(PROTECTED_DOMAINS) + extra))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisSettings":
        known = {k: v for k, v in (data or {}).items() if k in cls.__dataclass_fields__}
        return cls(**known)


GENERAL_LIMITATIONS = [
    "Headers can show that evidence supports or weakens a hypothesis; they cannot "
    "prove who wrote a message or whether an account was compromised.",
    "Received headers below the trust boundary are supplied by the sending side "
    "and may be forged.",
    "Authentication results are interpreted as recorded by the receiving server; "
    "signatures are not re-verified by this tool.",
    "Organisational domains use a built-in suffix list, not the full Public "
    "Suffix List; look-alike detection is heuristic and limited to protected domains.",
    "Message bodies, links and attachments are not analysed.",
]


def _limitations(parsed, route, auth, settings: AnalysisSettings) -> List[str]:
    items = list(GENERAL_LIMITATIONS)
    if parsed.headers_only:
        items.append("Only headers were supplied; fields may be missing because they "
                     "were not pasted.")
    if not auth.any_trusted:
        items.append("No trusted authentication results were available.")
    items.extend(auth.assumptions)
    if not settings.trusted_domains:
        items.append("Trusted infrastructure was inferred automatically "
                     f"({', '.join(route.trusted_domains) or 'none'}); configure "
                     "trusted domains for a stricter analysis.")
    if settings.dns_lookups:
        items.append("DNS lookups reflect the current DNS state, which may differ "
                     "from the state at delivery time.")
    return items


def _next_steps(findings, risk) -> List[str]:
    ids = {f.rule_id for f in findings}
    steps = []
    if risk.category != "low":
        steps.append("Do not act on requests in the message (payments, credentials, "
                     "attachments) until the sender is verified out-of-band.")
    if ids & {"AUTH-DMARC-FAIL", "AUTH-SPF-FAIL", "AUTH-NOT-ALIGNED"}:
        steps.append("Check the From domain's current SPF/DMARC records and compare "
                     "with the receiving server's logs for this Message-ID.")
    if ids & {"DOMAIN-LOOKALIKE", "DOMAIN-INTERNAL-LOOKALIKE"}:
        steps.append("Look up WHOIS / registration date of the look-alike domain and "
                     "report it to the impersonated organisation.")
    if "SENDER-REPLYTO-MISMATCH" in ids:
        steps.append("Confirm the Reply-To address with the apparent sender using a "
                     "known contact channel.")
    if ids & {"AUTH-MISSING", "ROUTE-MISSING", "HEADER-MISSING"}:
        steps.append("Obtain the complete original message (full headers) from the "
                     "recipient's mailbox or the mail server.")
    steps.append("Correlate the origin IP and Message-ID with mail-server and "
                 "gateway logs.")
    steps.append("Preserve this report together with the original file; verify the "
                 "SHA-256 hash before any further processing.")
    return steps


def analyze_email(raw: bytes, settings: Optional[AnalysisSettings] = None,
                  source_name: str = "", case_id: Optional[str] = None,
                  analysis_time: Optional[datetime] = None) -> dict:
    """Run the full pipeline.  Raises parser.InputError for unusable input."""
    settings = settings or AnalysisSettings()
    analysis_time = analysis_time or datetime.now(timezone.utc)
    parsed = parse_email(raw)
    route = analyze_route(parsed, settings.trusted_domains,
                          settings.clock_skew_minutes, now=analysis_time)
    auth = analyze_authentication(parsed, route, settings.trusted_authserv_ids,
                                  settings.dns_lookups)
    findings = detect_findings(parsed, route, auth, settings.all_protected_domains())
    risk = assess_risk(findings, settings.scoring_approach)

    parsed_dict = parsed.to_dict()
    parsed_dict["headers"] = [[sanitize_for_display(n, 200), sanitize_for_display(v)]
                              for n, v in parsed.headers]
    return {
        "metadata": {
            "case_id": case_id or new_case_id(analysis_time),
            "tool": TOOL_NAME,
            "tool_version": __version__,
            "analysis_time_utc": analysis_time.isoformat(),
            "source_name": source_name,
            "settings": settings.to_dict(),
        },
        "evidence": {"sha256": sha256_hex(bytes(raw)), "size_bytes": len(raw)},
        "parsed": parsed_dict,
        "route": route.to_dict(),
        "authentication": auth.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "risk": risk.to_dict(),
        "limitations": _limitations(parsed, route, auth, settings),
        "next_steps": _next_steps(findings, risk),
    }
