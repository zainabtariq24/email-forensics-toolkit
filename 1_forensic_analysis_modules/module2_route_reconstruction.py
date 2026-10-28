"""Module 2 - Email route reconstruction.

Each MTA *prepends* a Received header, so the topmost header is the most
recent hop and the bottom one is the (claimed) origin.  Only headers added by
infrastructure the investigator trusts can be relied upon; anything below the
trust boundary was supplied by the sending side and may be forged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable, List, Optional, Tuple

from module1_header_extraction import (ParsedEmail, classify_ip, extract_ips,
                                        organizational_domain, sanitize_for_display)

_KEYWORD_RE = re.compile(r"(from|by|via|with|id|for)\s", re.IGNORECASE)
_COMMENT_RE = re.compile(r"\([^()]*\)")
_HOST_RE = re.compile(r"^[A-Za-z0-9._\-\[\]:]+")

LONG_DELAY_SECONDS = 24 * 3600
DATE_AFTER_ROUTE_SECONDS = 3600
DATE_BEFORE_ROUTE_SECONDS = 3 * 24 * 3600


@dataclass
class Hop:
    delivery_index: int  # 1 = earliest claimed hop
    header_position: int  # 0 = topmost Received header
    raw: str
    from_helo: Optional[str] = None
    from_rdns: Optional[str] = None
    from_ip: Optional[str] = None
    from_ip_scope: Optional[str] = None
    by_host: Optional[str] = None
    protocol: Optional[str] = None
    smtp_id: Optional[str] = None
    for_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    timestamp_raw: Optional[str] = None
    delay_seconds: Optional[float] = None
    trusted: bool = False
    problems: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = dict(self.__dict__)
        data["raw"] = sanitize_for_display(self.raw)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data


@dataclass
class RouteAnomaly:
    kind: str
    severity: str
    detail: str
    hop_index: Optional[int] = None


@dataclass
class RouteAnalysis:
    hops: List[Hop]
    anomalies: List[RouteAnomaly]
    trusted_domains: List[str]
    handoff_hop_index: Optional[int]  # first hop received by trusted infra
    origin_ip: Optional[str]  # IP that connected to trusted infrastructure
    origin_ip_scope: Optional[str]
    claimed_origin_ip: Optional[str]  # earliest public IP anywhere (untrusted)
    total_transit_seconds: Optional[float]

    def to_dict(self) -> dict:
        return {
            "hops": [h.to_dict() for h in self.hops],
            "anomalies": [a.__dict__ for a in self.anomalies],
            "trusted_domains": self.trusted_domains,
            "handoff_hop_index": self.handoff_hop_index,
            "origin_ip": self.origin_ip,
            "origin_ip_scope": self.origin_ip_scope,
            "claimed_origin_ip": self.claimed_origin_ip,
            "total_transit_seconds": self.total_transit_seconds,
        }


def _split_clauses(text: str) -> List[Tuple[str, str]]:
    """Split a Received value into (keyword, text) clauses, ignoring keywords
    that appear inside parenthesised comments."""
    clauses: List[Tuple[str, str]] = []
    depth = 0
    key: Optional[str] = None
    start = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and (i == 0 or text[i - 1].isspace()):
            match = _KEYWORD_RE.match(text, i)
            if match:
                if key is not None:
                    clauses.append((key, text[start:i].strip()))
                key = match.group(1).lower()
                start = i = match.end()
                continue
        i += 1
    if key is not None:
        clauses.append((key, text[start:].strip()))
    return clauses


def _first_token(text: str) -> Optional[str]:
    match = _HOST_RE.match(text.strip())
    return match.group(0).strip(".").lower() if match else None


def _parse_timestamp(value: str) -> Optional[datetime]:
    cleaned = _COMMENT_RE.sub("", value).strip()
    try:
        parsed = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed is None or parsed.tzinfo is None:
        return None
    return parsed


def parse_received(value: str, header_position: int = 0) -> Hop:
    hop = Hop(delivery_index=0, header_position=header_position, raw=value)
    body, sep, date_part = value.rpartition(";")
    if not sep:
        body, date_part = value, ""
        hop.problems.append("No ';' separator, so no timestamp is present.")
    else:
        hop.timestamp_raw = date_part.strip()
        hop.timestamp = _parse_timestamp(date_part)
        if hop.timestamp is None:
            hop.problems.append("Timestamp could not be parsed.")

    clauses = _split_clauses(body)
    if not clauses:
        hop.problems.append("No recognisable from/by clauses.")
    for key, text in clauses:
        if key == "from" and hop.from_helo is None:
            hop.from_helo = _first_token(text)
            ips = extract_ips(text)
            if ips:
                hop.from_ip = ips[0]
                hop.from_ip_scope = classify_ip(ips[0])
            comment = re.search(r"\(([^)]*)\)", text)
            if comment:
                rdns = _first_token(comment.group(1))
                if rdns and not rdns.startswith("[") and not classify_ip(rdns) \
                        and rdns not in ("helo", "unknown") and "." in rdns:
                    hop.from_rdns = rdns
        elif key == "by" and hop.by_host is None:
            hop.by_host = _first_token(text)
        elif key == "with" and hop.protocol is None:
            hop.protocol = _first_token(text)
        elif key == "id" and hop.smtp_id is None:
            hop.smtp_id = _first_token(text)
        elif key == "for" and hop.for_address is None:
            hop.for_address = text.split()[0].strip("<>;") if text.strip() else None
    if hop.by_host is None:
        hop.problems.append("Missing 'by' clause (receiving host).")
    return hop


def _default_trusted_domains(hops_top_first: List[Hop]) -> List[str]:
    """Assume the organisation that operates the final receiving server is
    trusted; this mirrors where the recipient retrieved the message from."""
    for hop in hops_top_first:
        org = organizational_domain(hop.by_host) if hop.by_host else None
        if org and not classify_ip(hop.by_host.strip("[]")):
            return [org]
    return []


def analyze_route(parsed: ParsedEmail,
                  trusted_domains: Iterable[str] = (),
                  clock_skew_minutes: int = 5,
                  now: Optional[datetime] = None) -> RouteAnalysis:
    now = now or datetime.now(timezone.utc)
    top_first = [parse_received(v, i) for i, v in enumerate(parsed.received)]
    trusted = sorted({organizational_domain(d) for d in trusted_domains if d})
    if not trusted:
        trusted = _default_trusted_domains(top_first)

    # Trust walks downward from the top until the first hop that was not
    # recorded by trusted infrastructure.  A by-host that is a bare IP (as in
    # some provider-internal hops) inherits trust only at the very top.
    for i, hop in enumerate(top_first):
        by_org = organizational_domain(hop.by_host) if hop.by_host else None
        internal_ip_hop = bool(hop.by_host and classify_ip(hop.by_host.strip("[]")))
        if (by_org in trusted) or (internal_ip_hop and i == 0):
            hop.trusted = True
        else:
            break

    hops = list(reversed(top_first))
    for idx, hop in enumerate(hops, 1):
        hop.delivery_index = idx

    anomalies: List[RouteAnomaly] = []
    if not hops:
        anomalies.append(RouteAnomaly(
            "missing-route", "low" if not parsed.headers_only else "info",
            "No Received headers are present, so the delivery path cannot be "
            "reconstructed. Headers may have been stripped or only partially pasted."))

    skew = timedelta(minutes=clock_skew_minutes)
    previous: Optional[Hop] = None
    for hop in hops:
        for problem in hop.problems:
            anomalies.append(RouteAnomaly("malformed-hop", "info", problem,
                                          hop.delivery_index))
        if hop.timestamp and hop.timestamp - now > timedelta(days=1):
            anomalies.append(RouteAnomaly(
                "future-timestamp", "low",
                f"Hop {hop.delivery_index} is dated {hop.timestamp.isoformat()}, "
                "more than a day after the analysis time.", hop.delivery_index))
        if previous and previous.timestamp and hop.timestamp:
            delay = (hop.timestamp - previous.timestamp).total_seconds()
            hop.delay_seconds = delay
            if hop.timestamp + skew < previous.timestamp:
                anomalies.append(RouteAnomaly(
                    "time-reversal",
                    "medium" if -delay > 3600 else "low",
                    f"Hop {hop.delivery_index} ({hop.timestamp.isoformat()}) is "
                    f"{abs(delay) / 60:.1f} min earlier than hop "
                    f"{previous.delivery_index}; beyond the {clock_skew_minutes}-min "
                    "clock-skew tolerance.", hop.delivery_index))
            elif delay > LONG_DELAY_SECONDS:
                anomalies.append(RouteAnomaly(
                    "long-delay", "info",
                    f"Hop {hop.delivery_index} arrived {delay / 3600:.1f} h after the "
                    "previous hop (queueing, greylisting or re-sending).",
                    hop.delivery_index))
        if hop.timestamp:
            previous = hop

    handoff = next((h for h in hops if h.trusted), None)
    origin_ip = handoff.from_ip if handoff else None
    origin_scope = handoff.from_ip_scope if handoff else None
    claimed_origin = next((h.from_ip for h in hops
                           if h.from_ip and h.from_ip_scope == "public"), None)

    timed = [h.timestamp for h in hops if h.timestamp]
    total = (timed[-1] - timed[0]).total_seconds() if len(timed) >= 2 else None

    if parsed.date and timed:
        first, last = timed[0], timed[-1]
        if (parsed.date - last).total_seconds() > DATE_AFTER_ROUTE_SECONDS:
            anomalies.append(RouteAnomaly(
                "date-after-delivery", "low",
                f"Date header ({parsed.date.isoformat()}) is later than the final "
                f"delivery hop ({last.isoformat()}); a message cannot be written "
                "after it is delivered unless clocks are wrong or headers forged."))
        elif (first - parsed.date).total_seconds() > DATE_BEFORE_ROUTE_SECONDS:
            anomalies.append(RouteAnomaly(
                "date-long-before-route", "low",
                f"Date header ({parsed.date.isoformat()}) is more than 3 days "
                f"before the first hop ({first.isoformat()})."))
    if parsed.date and parsed.date - now > timedelta(days=1):
        anomalies.append(RouteAnomaly(
            "future-date", "low",
            f"Date header ({parsed.date.isoformat()}) is in the future."))

    if hops and handoff is None:
        anomalies.append(RouteAnomaly(
            "no-trusted-hop", "info",
            "None of the Received headers were added by a trusted server; the "
            "whole route is unverified."))

    return RouteAnalysis(
        hops=hops,
        anomalies=anomalies,
        trusted_domains=trusted,
        handoff_hop_index=handoff.delivery_index if handoff else None,
        origin_ip=origin_ip,
        origin_ip_scope=origin_scope,
        claimed_origin_ip=claimed_origin,
        total_transit_seconds=total,
    )
