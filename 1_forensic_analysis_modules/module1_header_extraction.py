"""Module 1 - Email ingestion and header extraction.

Turns a raw ``.eml`` file (or a block of pasted headers) into a structured
``ParsedEmail``.  The parser is deliberately tolerant: hostile or malformed
input must never crash the tool, so every problem is recorded as a
``HeaderIssue`` instead of raising, except for input that is unusable
altogether (empty, oversized or with no recognisable headers).
"""

from __future__ import annotations

import email
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email.header import decode_header, make_header
from email.policy import compat32
from email.utils import getaddresses, parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_HEADER_COUNT = 2000
MAX_DISPLAY_VALUE = 4000

# RFC 5322 section 3.6: these fields may appear at most once.
SINGLETON_FIELDS = (
    "From", "Sender", "Reply-To", "To", "Cc", "Bcc",
    "Message-ID", "In-Reply-To", "References", "Subject", "Date",
)
# RFC 5322 requires an origination date and an originator.
REQUIRED_FIELDS = ("From", "Date")
# Not mandatory, but virtually every legitimate MTA/MUA adds them.
EXPECTED_FIELDS = ("Message-ID", "To", "Subject")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)
_MESSAGE_ID_RE = re.compile(r"^<[^<>@\s]+@[^<>@\s]+>$")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_BRACKETED_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FOLDING_RE = re.compile(r"\r?\n[ \t]+")


class InputError(ValueError):
    """Raised when the input cannot be analysed at all."""


@dataclass
class HeaderIssue:
    field: str
    kind: str  # missing | duplicate | malformed | suspicious-encoding
    detail: str
    severity: str = "low"


@dataclass
class Address:
    display_name: str
    address: str
    domain: Optional[str]
    valid: bool

    def __str__(self) -> str:
        if self.display_name:
            return f'"{self.display_name}" <{self.address}>'
        return f"<{self.address}>"


@dataclass
class IPObservation:
    ip: str
    scope: str  # public | private | loopback | link-local | reserved | ...
    source: str


@dataclass
class ParsedEmail:
    headers: List[List[str]]  # [name, unfolded raw value] in original order
    from_addrs: List[Address] = field(default_factory=list)
    to_addrs: List[Address] = field(default_factory=list)
    cc_addrs: List[Address] = field(default_factory=list)
    reply_to: List[Address] = field(default_factory=list)
    sender: List[Address] = field(default_factory=list)
    return_path: Optional[Address] = None
    return_path_null: bool = False
    subject: Optional[str] = None
    message_id: Optional[str] = None
    message_id_domain: Optional[str] = None
    date_raw: Optional[str] = None
    date: Optional[datetime] = None
    received: List[str] = field(default_factory=list)  # top (newest) first
    authentication_results: List[str] = field(default_factory=list)
    arc_authentication_results: List[str] = field(default_factory=list)
    received_spf: List[str] = field(default_factory=list)
    dkim_signatures: List[str] = field(default_factory=list)
    ips: List[IPObservation] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    issues: List[HeaderIssue] = field(default_factory=list)
    has_body: bool = False
    headers_only: bool = False
    decoding_replacements: bool = False

    def get_all(self, name: str) -> List[str]:
        lname = name.lower()
        return [v for n, v in self.headers if n.lower() == lname]

    def get_first(self, name: str) -> Optional[str]:
        values = self.get_all(name)
        return values[0] if values else None

    def has(self, name: str) -> bool:
        return bool(self.get_all(name))

    @property
    def from_domain(self) -> Optional[str]:
        return self.from_addrs[0].domain if self.from_addrs else None

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["date"] = self.date.isoformat() if self.date else None
        data["from_domain"] = self.from_domain
        return data


def sanitize_for_display(value: str, limit: int = MAX_DISPLAY_VALUE) -> str:
    """Remove control characters and cap length so hostile values stay readable."""
    cleaned = _CONTROL_CHARS_RE.sub("�", value)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + f"... [truncated {len(value) - limit} chars]"
    return cleaned


def unfold(value: str) -> str:
    return _FOLDING_RE.sub(" ", value).strip()


def decode_words(value: str) -> str:
    """Decode RFC 2047 encoded-words, falling back to the raw value."""
    if "=?" not in value:
        return value
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # malformed encoded-words must not break analysis
        return value


def normalize_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    domain = domain.strip().strip(".").lower()
    return domain or None


def is_valid_domain(domain: Optional[str]) -> bool:
    if not domain:
        return False
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    return bool(_DOMAIN_RE.match(ascii_domain))


def classify_ip(ip_text: str) -> Optional[str]:
    """Return the scope of an IP address, or None if it is not a valid IP."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "public"
    return "other"


def extract_ips(text: str) -> List[str]:
    """Find syntactically valid IPv4/IPv6 addresses in a header value."""
    found: List[str] = []
    for candidate in _BRACKETED_IP_RE.findall(text) + _IPV4_RE.findall(text):
        if classify_ip(candidate) and candidate not in found:
            found.append(candidate)
    return found


def parse_address(display_name: str, addr: str) -> Address:
    addr = addr.strip()
    domain = None
    valid = False
    if "@" in addr:
        local, _, dom = addr.rpartition("@")
        domain = normalize_domain(dom)
        valid = bool(local) and is_valid_domain(domain)
    return Address(
        display_name=decode_words(display_name).strip(),
        address=addr,
        domain=domain,
        valid=valid,
    )


def parse_address_list(value: str) -> List[Address]:
    pairs = getaddresses([value])
    return [parse_address(name, addr) for name, addr in pairs if addr or name]


def _parse_date(value: str) -> Optional[datetime]:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed is None or parsed.tzinfo is None:
        # A date without a timezone cannot be ordered against other evidence.
        return None
    return parsed


def _decode_input(raw: bytes) -> Tuple[str, bool]:
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        # Keep going but remember that bytes were replaced.
        return raw.decode("utf-8", errors="replace"), True


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse raw message bytes (full .eml or headers only)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise InputError("Input must be bytes.")
    if len(raw) == 0:
        raise InputError("Input is empty.")
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError(
            f"Input is {len(raw)} bytes; the limit is {MAX_INPUT_BYTES} bytes."
        )

    text, replaced = _decode_input(bytes(raw))
    text = text.replace("\x00", "�")
    # Pasted headers often start with blank lines or indentation.
    text = text.lstrip("\r\n﻿")

    msg = email.message_from_string(text, policy=compat32)
    raw_items = msg.items()
    if not raw_items:
        raise InputError("No email headers were found in the input.")

    # Check the raw text: the summary's wrapped "to:" line stops header parsing
    # before the mailed-by/signed-by lines are reached.
    if (re.search(r"^(mailed-by|signed-by):", text, re.IGNORECASE | re.MULTILINE)
            and not re.search(r"^(received|message-id):", text,
                              re.IGNORECASE | re.MULTILINE)):
        raise InputError(
            "This looks like Gmail's sender-details summary, not the raw headers. "
            "In Gmail open the message, choose \u22ee > Show original > Copy to "
            "clipboard, and paste that instead.")

    headers: List[List[str]] = []
    for name, value in raw_items[:MAX_HEADER_COUNT]:
        headers.append([str(name).strip(), unfold(str(value))])

    body = msg.get_payload()
    has_body = bool(body) if not msg.is_multipart() else True
    parsed = ParsedEmail(
        headers=headers,
        has_body=has_body,
        headers_only=not has_body,
        decoding_replacements=replaced,
    )

    if len(raw_items) > MAX_HEADER_COUNT:
        parsed.issues.append(HeaderIssue(
            "*", "malformed",
            f"{len(raw_items)} header fields present; only the first "
            f"{MAX_HEADER_COUNT} were analysed.", "medium"))
    if replaced:
        parsed.issues.append(HeaderIssue(
            "*", "suspicious-encoding",
            "Input contained bytes that are not valid UTF-8; they were "
            "replaced with U+FFFD for analysis (the original file is preserved).",
            "info"))
    for defect in msg.defects:
        parsed.issues.append(HeaderIssue(
            "*", "malformed", f"Parser defect: {type(defect).__name__}", "info"))
    for name, _ in headers:
        if not re.match(r"^[\x21-\x39\x3b-\x7e]+$", name):
            parsed.issues.append(HeaderIssue(
                sanitize_for_display(name, 80), "malformed",
                "Header field name contains characters not permitted by RFC 5322.",
                "low"))

    _extract_fields(parsed)
    _check_presence_and_duplicates(parsed)
    _collect_ips_and_domains(parsed)
    return parsed


def _extract_fields(parsed: ParsedEmail) -> None:
    def addresses(field_name: str) -> List[Address]:
        result: List[Address] = []
        for value in parsed.get_all(field_name):
            result.extend(parse_address_list(value))
        return result

    parsed.from_addrs = addresses("From")
    parsed.to_addrs = addresses("To")
    parsed.cc_addrs = addresses("Cc")
    parsed.reply_to = addresses("Reply-To")
    parsed.sender = addresses("Sender")

    for field_name, addrs in (("From", parsed.from_addrs),
                              ("Reply-To", parsed.reply_to),
                              ("Sender", parsed.sender)):
        if parsed.has(field_name) and not addrs:
            parsed.issues.append(HeaderIssue(
                field_name, "malformed", "No address could be parsed.", "medium"))
        for addr in addrs:
            if not addr.valid:
                parsed.issues.append(HeaderIssue(
                    field_name, "malformed",
                    f"Invalid address: {sanitize_for_display(addr.address, 200)!r}",
                    "medium" if field_name == "From" else "low"))
    if len(parsed.from_addrs) > 1 and not parsed.sender:
        parsed.issues.append(HeaderIssue(
            "From", "malformed",
            "Multiple From addresses without a Sender field (RFC 5322 3.6.2).",
            "low"))

    return_path = parsed.get_first("Return-Path")
    if return_path is not None:
        stripped = return_path.strip()
        if stripped in ("<>", ""):
            parsed.return_path_null = True
        else:
            rp = parse_address_list(stripped)
            if rp:
                parsed.return_path = rp[0]
                if not rp[0].valid:
                    parsed.issues.append(HeaderIssue(
                        "Return-Path", "malformed",
                        f"Invalid address: {sanitize_for_display(stripped, 200)!r}",
                        "low"))

    subject = parsed.get_first("Subject")
    if subject is not None:
        parsed.subject = sanitize_for_display(decode_words(subject), 1000)

    message_id = parsed.get_first("Message-ID")
    if message_id is not None:
        parsed.message_id = message_id.strip()
        if _MESSAGE_ID_RE.match(parsed.message_id):
            parsed.message_id_domain = normalize_domain(
                parsed.message_id[1:-1].rpartition("@")[2])
        else:
            parsed.issues.append(HeaderIssue(
                "Message-ID", "malformed",
                "Message-ID is not of the form <id-left@id-right> (RFC 5322 3.6.4).",
                "low"))

    date_raw = parsed.get_first("Date")
    if date_raw is not None:
        parsed.date_raw = date_raw
        parsed.date = _parse_date(date_raw)
        if parsed.date is None:
            parsed.issues.append(HeaderIssue(
                "Date", "malformed",
                "Date could not be parsed as an RFC 5322 date with a timezone.",
                "low"))

    parsed.received = parsed.get_all("Received")
    parsed.authentication_results = parsed.get_all("Authentication-Results")
    parsed.arc_authentication_results = parsed.get_all("ARC-Authentication-Results")
    parsed.received_spf = parsed.get_all("Received-SPF")
    parsed.dkim_signatures = parsed.get_all("DKIM-Signature")


def _check_presence_and_duplicates(parsed: ParsedEmail) -> None:
    for name in REQUIRED_FIELDS:
        if not parsed.has(name):
            parsed.issues.append(HeaderIssue(
                name, "missing", f"Required field {name} is absent (RFC 5322).",
                "medium"))
    for name in EXPECTED_FIELDS:
        if not parsed.has(name):
            parsed.issues.append(HeaderIssue(
                name, "missing",
                f"{name} is absent; almost all legitimate mail carries it.",
                "low" if name == "Message-ID" else "info"))
    for name in SINGLETON_FIELDS:
        count = len(parsed.get_all(name))
        if count > 1:
            severity = "high" if name in ("From", "Sender") else "medium"
            parsed.issues.append(HeaderIssue(
                name, "duplicate",
                f"{name} appears {count} times; RFC 5322 allows at most one. "
                "Different mail clients may display different copies.",
                severity))


def _collect_ips_and_domains(parsed: ParsedEmail) -> None:
    seen = set()
    sources = [("Received", v) for v in parsed.received]
    sources += [("Received-SPF", v) for v in parsed.received_spf]
    sources += [(n, v) for n, v in parsed.headers
                if n.lower() in ("x-originating-ip", "x-sender-ip")]
    for source, value in sources:
        for ip in extract_ips(value):
            if ip in seen:
                continue
            seen.add(ip)
            parsed.ips.append(IPObservation(ip=ip, scope=classify_ip(ip) or "invalid",
                                            source=source))

    domains: List[str] = []
    for addr in (parsed.from_addrs + parsed.reply_to + parsed.sender
                 + ([parsed.return_path] if parsed.return_path else [])):
        if addr.domain and addr.domain not in domains:
            domains.append(addr.domain)
    if parsed.message_id_domain and parsed.message_id_domain not in domains:
        domains.append(parsed.message_id_domain)
    parsed.domains = domains


# ----------------------------------------------------------------------------
# Domain helpers shared by every later module.  Organisational domains are
# approximated with a small built-in list of multi-label public suffixes
# rather than the full Public Suffix List, so the tool works offline.
# ----------------------------------------------------------------------------

MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "co.in", "ac.in", "gov.in", "net.in", "org.in",
    "com.pk", "edu.pk", "gov.pk", "org.pk", "net.pk",
    "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.my",
    "com.sa", "com.ng", "com.eg", "co.za", "co.kr", "com.hk", "com.tw",
}


def organizational_domain(domain: Optional[str]) -> Optional[str]:
    """Approximate the registrable ('organisational') domain."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    if len(labels) < 2:
        return domain.lower()
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def registrable_label(domain: str) -> str:
    """The label a registrant chose, e.g. 'paypal' for 'mail.paypal.co.uk'."""
    org = organizational_domain(domain) or domain
    return org.split(".")[0]


def same_organization(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    return organizational_domain(a) == organizational_domain(b)
