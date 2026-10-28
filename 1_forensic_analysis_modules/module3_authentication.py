"""Module 3 - Email authentication analysis (SPF, DKIM, DMARC, ARC).

The tool does not re-verify signatures; it interprets the results that the
receiving server *recorded*.  Those records are only meaningful when they come
from a trusted authentication service, because any sender can insert a fake
``Authentication-Results`` header further down the message.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from module1_header_extraction import (ParsedEmail, normalize_domain,
                                        organizational_domain)
from module2_route_reconstruction import RouteAnalysis

_PROP_RE = re.compile(r"([a-z]+)\.([a-z0-9_-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)", re.I)
_METHOD_RE = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z]+)", re.I)
_COMMENT_RE = re.compile(r"\(([^()]*)\)")

NORMALIZED = {
    "pass": "pass",
    "fail": "fail", "softfail": "fail", "policy": "fail", "hardfail": "fail",
    "neutral": "neutral", "none": "neutral",
    "temperror": "inconclusive", "permerror": "inconclusive",
}

EXPLANATIONS = {
    "spf": {
        "pass": "The connecting IP is authorised by the SPF record of the envelope "
                "sender (Return-Path) domain. SPF says nothing about the visible From.",
        "fail": "The connecting IP is NOT authorised by the envelope sender's SPF "
                "record. Common for spoofing, but also for forwarded mail.",
        "softfail": "The domain's SPF record marks the IP as probably unauthorised (~all).",
        "neutral": "The domain makes no assertion about this IP, or publishes no SPF record.",
        "inconclusive": "SPF evaluation hit a temporary or permanent error.",
        "missing": "No trusted SPF result was recorded.",
    },
    "dkim": {
        "pass": "A DKIM signature verified, so the signed headers/body were not altered "
                "after signing by the signing domain (d=).",
        "fail": "A DKIM signature failed verification: content was altered or the "
                "signature is forged. Mailing lists that edit messages also cause this.",
        "neutral": "The message was not signed, or the signature could not be evaluated.",
        "inconclusive": "DKIM evaluation hit a temporary or permanent error (e.g. DNS).",
        "missing": "No trusted DKIM result was recorded.",
    },
    "dmarc": {
        "pass": "SPF or DKIM passed for a domain aligned with the visible From domain.",
        "fail": "Neither SPF nor DKIM produced a pass aligned with the visible From "
                "domain. This is the strongest header-level sign of From spoofing.",
        "neutral": "The From domain publishes no DMARC policy, so alignment was not enforced.",
        "inconclusive": "DMARC evaluation hit a temporary or permanent error.",
        "missing": "No trusted DMARC result was recorded.",
    },
}


@dataclass
class MethodResult:
    method: str
    result: str
    properties: Dict[str, str]
    comment: str
    authserv_id: Optional[str]
    source: str  # Authentication-Results | ARC-Authentication-Results | Received-SPF
    header_index: int
    trusted: bool = False


@dataclass
class MechanismSummary:
    mechanism: str
    status: str  # pass | fail | neutral | missing | inconclusive
    raw_result: Optional[str]
    domain: Optional[str]
    source: Optional[str]
    explanation: str
    details: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthenticationAnalysis:
    spf: MechanismSummary
    dkim: MechanismSummary
    dmarc: MechanismSummary
    arc: Optional[MechanismSummary]
    results: List[MethodResult]
    trusted_authserv_ids: List[str]
    untrusted_results: List[MethodResult]
    alignment: Dict[str, object]
    dkim_passing_domains: List[str]
    assumptions: List[str]
    dns: Dict[str, object] = field(default_factory=dict)

    @property
    def any_trusted(self) -> bool:
        return any(r.trusted for r in self.results)

    def to_dict(self) -> dict:
        return {
            "spf": self.spf.__dict__, "dkim": self.dkim.__dict__,
            "dmarc": self.dmarc.__dict__,
            "arc": self.arc.__dict__ if self.arc else None,
            "results": [r.__dict__ for r in self.results],
            "trusted_authserv_ids": self.trusted_authserv_ids,
            "untrusted_result_count": len(self.untrusted_results),
            "alignment": self.alignment,
            "dkim_passing_domains": self.dkim_passing_domains,
            "assumptions": self.assumptions,
            "dns": self.dns,
        }


def _split_top_level(value: str, sep: str = ";") -> List[str]:
    parts, depth, quote, buf = [], 0, False, []
    for ch in value:
        if ch == '"' and depth == 0:
            quote = not quote
        elif ch == "(" and not quote:
            depth += 1
        elif ch == ")" and not quote:
            depth = max(0, depth - 1)
        if ch == sep and depth == 0 and not quote:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def parse_authentication_results(value: str, header_index: int = 0,
                                 source: str = "Authentication-Results"
                                 ) -> Tuple[Optional[str], List[MethodResult]]:
    """Parse one Authentication-Results (RFC 8601) or ARC-A-R header value."""
    segments = _split_top_level(value)
    if not segments:
        return None, []
    authserv_id: Optional[str] = None
    if source == "ARC-Authentication-Results" and segments[0].lower().startswith("i="):
        segments = segments[1:]
    first = _COMMENT_RE.sub("", segments[0]).strip()
    if first and not _METHOD_RE.match(first):
        # First segment is the authserv-id (optionally followed by a version).
        authserv_id = first.split()[0].lower()
        segments = segments[1:]
    results: List[MethodResult] = []
    for seg in segments:
        match = _METHOD_RE.match(seg)
        if not match:
            continue
        method, result = match.group(1).lower(), match.group(2).lower()
        comments = " ".join(_COMMENT_RE.findall(seg))
        props = {f"{p.lower()}.{k.lower()}": v.strip('"')
                 for p, k, v in _PROP_RE.findall(_COMMENT_RE.sub(" ", seg))}
        for extra in re.findall(r"\b(action|reason|p|sp|dis)\s*=\s*(\"[^\"]*\"|[^\s;)]+)",
                                seg, re.I):
            props.setdefault(extra[0].lower(), extra[1].strip('"'))
        results.append(MethodResult(method, result, props, comments, authserv_id,
                                    source, header_index))
    return authserv_id, results


def parse_received_spf(value: str, header_index: int = 0) -> Optional[MethodResult]:
    match = re.match(r"\s*([a-z]+)", value, re.I)
    if not match:
        return None
    props = {}
    for key, val in re.findall(r"([a-z-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)", value, re.I):
        props[key.lower()] = val.strip('"')
    mailfrom = props.get("envelope-from")
    if mailfrom:
        props["smtp.mailfrom"] = mailfrom.strip("<>")
    return MethodResult("spf", match.group(1).lower(), props,
                        " ".join(_COMMENT_RE.findall(value)), None,
                        "Received-SPF", header_index)


def _domain_from(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip("<>")
    return normalize_domain(value.rpartition("@")[2]) if value else None


def _summarize(mechanism: str, results: List[MethodResult]) -> MechanismSummary:
    relevant = [r for r in results if r.method == mechanism]
    if not relevant:
        return MechanismSummary(mechanism, "missing", None, None, None,
                                EXPLANATIONS[mechanism]["missing"])
    chosen = relevant[0]
    if mechanism == "dkim":
        # One valid signature is enough; report the best outcome.
        for wanted in ("pass", "fail", "softfail", "policy", "neutral", "none",
                       "temperror", "permerror"):
            match = next((r for r in relevant if r.result == wanted), None)
            if match:
                chosen = match
                break
    status = NORMALIZED.get(chosen.result, "inconclusive")
    if mechanism == "spf":
        domain = _domain_from(chosen.properties.get("smtp.mailfrom")) or \
            _domain_from(chosen.properties.get("smtp.helo"))
    elif mechanism == "dkim":
        domain = normalize_domain(chosen.properties.get("header.d")) or \
            _domain_from(chosen.properties.get("header.i"))
    else:
        domain = normalize_domain(chosen.properties.get("header.from"))
    explanation_key = "softfail" if chosen.result == "softfail" and mechanism == "spf" \
        else status
    explanation = EXPLANATIONS[mechanism].get(explanation_key,
                                              EXPLANATIONS[mechanism][status])
    if chosen.result == "none":
        explanation = ("No record/signature exists ('none'): " +
                       EXPLANATIONS[mechanism]["neutral"])
    details = {k: v for k, v in chosen.properties.items()}
    if chosen.comment:
        details["comment"] = chosen.comment
    return MechanismSummary(mechanism, status, chosen.result, domain,
                            f"{chosen.source} ({chosen.authserv_id or 'no authserv-id'})",
                            explanation, details)


def analyze_authentication(parsed: ParsedEmail, route: RouteAnalysis,
                           trusted_authserv_ids: Optional[List[str]] = None,
                           dns_lookups: bool = False) -> AuthenticationAnalysis:
    assumptions: List[str] = []
    results: List[MethodResult] = []
    authserv_order: List[Optional[str]] = []
    for i, value in enumerate(parsed.authentication_results):
        authserv, parsed_results = parse_authentication_results(value, i)
        authserv_order.append(authserv)
        results.extend(parsed_results)

    trusted_ids = [t.lower() for t in (trusted_authserv_ids or []) if t.strip()]
    if not trusted_ids and parsed.authentication_results:
        top = authserv_order[0]
        top_org = organizational_domain(top) if top else None
        if top is None:
            # e.g. Microsoft 365 omits the authserv-id; trust only the topmost header.
            assumptions.append(
                "The topmost Authentication-Results header has no authserv-id "
                "(typical of Microsoft 365); only that header was trusted.")
            for r in results:
                r.trusted = r.header_index == 0
        elif not route.trusted_domains or top_org in route.trusted_domains:
            trusted_ids = [top]
            assumptions.append(
                f"Auto-trusted authserv-id '{top}' (topmost Authentication-Results"
                + (", matching the receiving server's domain)." if route.trusted_domains
                   else "; no Received headers to corroborate it)."))
        else:
            assumptions.append(
                f"Topmost authserv-id '{top}' does not belong to the receiving "
                f"domain(s) {route.trusted_domains}; no results were trusted. "
                "Configure trusted authserv-ids to override.")
    for r in results:
        if r.authserv_id and r.authserv_id in trusted_ids:
            r.trusted = True

    trusted_results = [r for r in results if r.trusted]
    untrusted = [r for r in results if not r.trusted]

    # Received-SPF is only used when no trusted A-R SPF result exists.
    if not any(r.method == "spf" for r in trusted_results) and parsed.received_spf:
        spf = parse_received_spf(parsed.received_spf[0], 0)
        if spf:
            # Trusted only if it sits above every Received header that was
            # added outside the trusted infrastructure.
            names = [n.lower() for n, _ in parsed.headers]
            spf_pos = names.index("received-spf")
            received_pos = [i for i, n in enumerate(names) if n == "received"]
            untrusted_hops = [h for h in route.hops if not h.trusted]
            first_untrusted = (received_pos[min(h.header_position for h in untrusted_hops)]
                               if untrusted_hops else None)
            spf.trusted = bool(route.hops) and (
                first_untrusted is None or spf_pos < first_untrusted)
            if spf.trusted:
                assumptions.append("SPF taken from the topmost Received-SPF header.")
                trusted_results.append(spf)
            else:
                untrusted.append(spf)
            results.append(spf)

    spf_summary = _summarize("spf", trusted_results)
    dkim_summary = _summarize("dkim", trusted_results)
    dmarc_summary = _summarize("dmarc", trusted_results)
    arc_results = [r for r in trusted_results if r.method == "arc"]
    arc_summary = None
    if arc_results or parsed.arc_authentication_results:
        arc_summary = MechanismSummary(
            "arc", NORMALIZED.get(arc_results[0].result, "inconclusive")
            if arc_results else "missing",
            arc_results[0].result if arc_results else None, None,
            "Authentication-Results" if arc_results else None,
            "ARC preserves authentication results across forwarders/lists. "
            "A trusted arc=pass means the chain of intermediaries is intact; "
            "it does not prove the intermediaries themselves are trustworthy.")
        # Record what the first intermediary saw (i=1), if present.
        for value in parsed.arc_authentication_results:
            if re.match(r"\s*i\s*=\s*1\s*;", value):
                _, original = parse_authentication_results(
                    value, 0, "ARC-Authentication-Results")
                for r in original:
                    arc_summary.details[f"original_{r.method}"] = r.result

    # Gmail reports the signing identity as header.i=@domain rather than header.d.
    dkim_passing = sorted({d for d in (
        normalize_domain(r.properties.get("header.d"))
        or _domain_from(r.properties.get("header.i"))
        for r in trusted_results if r.method == "dkim" and r.result == "pass") if d})
    from_domain = parsed.from_domain
    from_org = organizational_domain(from_domain)
    spf_domain = spf_summary.domain or (parsed.return_path.domain
                                        if parsed.return_path else None)
    spf_aligned = spf_summary.status == "pass" and bool(from_org) and \
        organizational_domain(spf_domain) == from_org
    dkim_aligned = bool(from_org) and any(
        organizational_domain(d) == from_org for d in dkim_passing)
    alignment = {
        "from_domain": from_domain,
        "spf_domain": spf_domain,
        "spf_aligned": spf_aligned,
        "dkim_domains": dkim_passing,
        "dkim_aligned": dkim_aligned,
        "computed_dmarc_alignment": "pass" if (spf_aligned or dkim_aligned) else "fail",
        "note": "Relaxed alignment computed by this tool from the trusted results; "
                "it approximates, but is not, a DMARC evaluation.",
    }

    analysis = AuthenticationAnalysis(
        spf=spf_summary, dkim=dkim_summary, dmarc=dmarc_summary, arc=arc_summary,
        results=results, trusted_authserv_ids=trusted_ids, untrusted_results=untrusted,
        alignment=alignment, dkim_passing_domains=dkim_passing, assumptions=assumptions,
    )
    if dns_lookups and from_domain:
        analysis.dns = lookup_dns_policies(from_domain)
    return analysis


def lookup_dns_policies(domain: str, timeout: float = 3.0) -> Dict[str, object]:
    """Optional live SPF/DMARC lookups.  DNS shows the *current* policy, which
    may differ from the policy in force when the message was delivered."""
    info: Dict[str, object] = {"domain": domain,
                               "note": "Current DNS state, not state at delivery time."}
    try:
        import dns.resolver
    except ImportError:
        info["error"] = "dnspython is not installed."
        return info
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    def txt(name: str) -> List[str]:
        try:
            answers = resolver.resolve(name, "TXT")
        except Exception as exc:  # NXDOMAIN, timeout, no answer...
            return [f"<lookup failed: {type(exc).__name__}>"]
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]

    spf = [t for t in txt(domain) if t.lower().startswith("v=spf1") or t.startswith("<")]
    dmarc_domain = organizational_domain(domain) or domain
    dmarc = [t for t in txt(f"_dmarc.{domain}")
             if t.lower().startswith("v=dmarc1") or t.startswith("<")]
    if dmarc and dmarc[0].startswith("<") and dmarc_domain != domain:
        dmarc = [t for t in txt(f"_dmarc.{dmarc_domain}")
                 if t.lower().startswith("v=dmarc1") or t.startswith("<")]
    info["spf_record"] = spf[0] if spf else None
    info["dmarc_record"] = dmarc[0] if dmarc else None
    if dmarc and not dmarc[0].startswith("<"):
        policy = re.search(r"\bp\s*=\s*(\w+)", dmarc[0], re.I)
        info["dmarc_policy"] = policy.group(1).lower() if policy else None
    return info
