"""Module 4 - Spoofing and anomaly detection (including look-alike domains).

Every rule produces a ``Finding`` that states the evidence, why it matters,
its severity and its limitations.  A finding is an *indicator*: it supports
or weakens a hypothesis, it never proves malicious intent on its own.

Rule catalogue (IDs are referenced by risk_assessment.RULE_WEIGHTS):

    AUTH-DMARC-FAIL        trusted DMARC result is fail
    AUTH-SPF-FAIL          trusted SPF result is fail / softfail
    AUTH-DKIM-FAIL         DKIM failed and no signature passed
    AUTH-NOT-ALIGNED       auth passed, but for a domain unrelated to From
    AUTH-MISSING           no trusted authentication results at all
    AUTH-UNTRUSTED-CLAIMS  untrusted A-R headers claim results the trusted one does not
    SENDER-REPLYTO-MISMATCH    Reply-To organisation differs from From
    SENDER-RETURNPATH-MISMATCH envelope sender organisation differs from From
    SENDER-DISPLAYNAME-ADDRESS display name contains a different e-mail address
    SENDER-DISPLAYNAME-BRAND   display name invokes a brand the domain does not own
    DOMAIN-LOOKALIKE           a sender-side domain imitates a protected domain
    DOMAIN-INTERNAL-LOOKALIKE  Reply-To/Return-Path near-identical to From
    HEADER-DUPLICATE           singleton header fields repeated
    HEADER-MISSING             required/expected fields absent
    HEADER-MALFORMED           fields that do not parse
    ROUTE-INCONSISTENT         timestamp reversals or Date/route disagreement
    ROUTE-MISSING              no Received headers
    MSGID-DOMAIN-MISMATCH      Message-ID domain unrelated to From (weak)
    CONTEXT-MAILING-LIST       message shows mailing-list markers (mitigating)
    CONTEXT-FORWARDED          message shows forwarding / ARC markers (mitigating)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Iterable, List, Optional

from module1_header_extraction import (ParsedEmail, organizational_domain,
                                        registrable_label, same_organization,
                                        sanitize_for_display)
from module2_route_reconstruction import RouteAnalysis
from module3_authentication import AuthenticationAnalysis

# ============================================================================
# Part A - look-alike domain detection
# ============================================================================

try:
    import idna as _idna
except ImportError:  # pragma: no cover - idna is in requirements.txt
    _idna = None

# Frequently impersonated domains.  Organisation-specific domains are added
# at analysis time through AnalysisSettings.protected_domains.
PROTECTED_DOMAINS = (
    "paypal.com", "apple.com", "icloud.com", "microsoft.com", "outlook.com",
    "office.com", "office365.com", "live.com", "google.com", "gmail.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "linkedin.com", "dropbox.com", "docusign.com", "adobe.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citibank.com", "hsbc.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com", "github.com", "yahoo.com",
    "ebay.com", "coinbase.com", "binance.com", "steampowered.com",
    "whatsapp.com", "zoom.us", "wetransfer.com", "hbl.com", "meezanbank.com",
)

# Domains that legitimately contain a protected brand name.
KNOWN_RELATED_DOMAINS = {
    "amazonses.com": "amazon.com", "amazonaws.com": "amazon.com",
    "googlemail.com": "google.com", "google-analytics.com": "google.com",
    "microsoftonline.com": "microsoft.com", "office365.com": "microsoft.com",
    "outlook.com": "microsoft.com", "live.com": "microsoft.com",
    "sharepointonline.com": "microsoft.com", "facebookmail.com": "facebook.com",
    "paypal-communication.com": "paypal.com", "paypal-community.com": "paypal.com",
    "linkedinmobileapp.com": "linkedin.com", "appleid.com": "apple.com",
    "docusign.net": "docusign.com", "githubusercontent.com": "github.com",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "mail.com", "gmx.com", "proton.me",
    "protonmail.com", "yandex.com", "zoho.com",
}

# Visual confusables that matter for domains (subset of Unicode TR39).
_UNICODE_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q",
    "ԝ": "w", "ɑ": "a", "ο": "o", "α": "a", "ν": "v", "τ": "t", "κ": "k",
    "ı": "i", "ɡ": "g", "ł": "l", "ø": "o",
}
# ASCII substitutions commonly used in typosquats.
_ASCII_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"),
                     ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"),
                     ("7", "t"), ("8", "b"), ("|", "l"), ("i", "l"))


@dataclass
class LookalikeMatch:
    domain: str
    resembles: str
    technique: str
    detail: str


def to_ascii(domain: str) -> str:
    """Convert an IDN to its ASCII (punycode) form where possible."""
    try:
        if _idna is not None:
            return _idna.encode(domain, uts46=True).decode("ascii")
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


def to_unicode(domain: str) -> str:
    """Decode punycode labels (xn--) to Unicode for display and comparison."""
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                label = (_idna.decode(label) if _idna is not None
                         else label.encode("ascii").decode("idna"))
            except Exception:
                pass
        labels.append(label)
    return ".".join(labels)


def is_freemail(domain: Optional[str]) -> bool:
    return bool(domain) and organizational_domain(domain) in FREEMAIL_DOMAINS


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def unicode_skeleton(text: str) -> str:
    """Map visually confusable Unicode characters to ASCII look-alikes."""
    out = []
    for ch in text.lower():
        if ch in _UNICODE_CONFUSABLES:
            out.append(_UNICODE_CONFUSABLES[ch])
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        base = "".join(c for c in decomposed if not unicodedata.combining(c))
        out.append(base if base else ch)
    return "".join(out)


def ascii_skeleton(text: str) -> str:
    for old, new in _ASCII_HOMOGLYPHS:
        text = text.replace(old, new)
    return text


def scripts_used(text: str) -> List[str]:
    scripts = set()
    for ch in text:
        if ch.isascii():
            if ch.isalpha():
                scripts.add("LATIN")
            continue
        try:
            scripts.add(unicodedata.name(ch).split(" ")[0])
        except ValueError:
            scripts.add("UNKNOWN")
    return sorted(scripts)


def _is_protected_or_related(domain: str, protected: Iterable[str]) -> bool:
    org = organizational_domain(domain)
    return org in protected or org in KNOWN_RELATED_DOMAINS


def check_lookalike(domain: Optional[str],
                    protected: Iterable[str] = PROTECTED_DOMAINS
                    ) -> List[LookalikeMatch]:
    """Compare a domain against protected domains using several techniques."""
    if not domain:
        return []
    protected = [p.lower() for p in protected]
    unicode_domain = to_unicode(domain.lower())
    if _is_protected_or_related(unicode_domain, protected):
        return []

    matches: List[LookalikeMatch] = []
    label = registrable_label(unicode_domain)
    org = organizational_domain(unicode_domain) or unicode_domain
    non_ascii = not unicode_domain.isascii()
    skeleton = unicode_skeleton(label)

    for target in protected:
        t_label = registrable_label(target)
        if len(t_label) < 3:
            continue
        if non_ascii and ascii_skeleton(skeleton) == ascii_skeleton(t_label):
            matches.append(LookalikeMatch(
                domain, target, "idn-homograph",
                f"'{unicode_domain}' uses non-Latin characters "
                f"({', '.join(scripts_used(label))}) that render like '{t_label}'."))
            continue
        if label != t_label and ascii_skeleton(label) == ascii_skeleton(t_label):
            matches.append(LookalikeMatch(
                domain, target, "character-substitution",
                f"'{label}' becomes '{t_label}' after swapping visually similar "
                "characters (e.g. 1/l, 0/o, rn/m)."))
            continue
        distance = levenshtein(label, t_label)
        if label != t_label and len(t_label) >= 5 and (
                distance == 1 or (distance == 2 and len(t_label) >= 8)):
            matches.append(LookalikeMatch(
                domain, target, "typosquat",
                f"'{label}' is {distance} edit(s) away from '{t_label}'."))
            continue
        if label == t_label and org != target:
            matches.append(LookalikeMatch(
                domain, target, "suffix-swap",
                f"Same name as '{target}' under a different suffix ('{org}'); "
                "some organisations legitimately own several suffixes."))
            continue
        tokens = label.replace("_", "-").split("-")
        # Prefix-only substring match avoids e.g. 'purchase' -> 'chase'.
        if len(t_label) >= 4 and (t_label in tokens or (
                len(t_label) >= 5 and label.startswith(t_label)
                and label != t_label)):
            matches.append(LookalikeMatch(
                domain, target, "brand-embedded",
                f"Registrable domain '{org}' embeds the brand name '{t_label}' "
                f"but is not owned by {target}."))
            continue
        if (f".{target}." in f".{unicode_domain}."
                and not unicode_domain.endswith("." + target)
                and unicode_domain != target):
            matches.append(LookalikeMatch(
                domain, target, "brand-in-subdomain",
                f"'{target}' appears as a sub-domain prefix of '{org}', which "
                "is the domain that actually controls the address."))
    return matches


def compare_related_domains(primary: Optional[str], other: Optional[str]
                            ) -> Optional[LookalikeMatch]:
    """Detect when two domains in the same message are near-identical
    (e.g. From: acme-supplies.com vs Reply-To: acme-suppIies.com)."""
    if not primary or not other or same_organization(primary, other):
        return None
    a = registrable_label(to_unicode(primary.lower()))
    b = registrable_label(to_unicode(other.lower()))
    if len(a) < 4:
        return None
    if ascii_skeleton(unicode_skeleton(a)) == ascii_skeleton(unicode_skeleton(b)):
        return LookalikeMatch(other, primary, "character-substitution",
                              f"'{b}' is visually equivalent to '{a}'.")
    distance = levenshtein(a, b)
    if 0 < distance <= (1 if len(a) < 8 else 2):
        return LookalikeMatch(other, primary, "typosquat",
                              f"'{b}' is {distance} edit(s) away from '{a}'.")
    return None


# ============================================================================
# Part B - spoofing and anomaly rules
# ============================================================================

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str  # authentication | sender | domain | header | route | context
    evidence: List[str]
    why_it_matters: str
    limitations: str
    mitigated_by: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MessageContext:
    mailing_list: bool
    forwarded: bool
    bulk_sender: bool
    arc_pass: bool
    markers: List[str]


def _tag(value: str, name: str) -> Optional[str]:
    match = re.search(rf"(?:^|;)\s*{name}\s*=\s*([^;\s]+)", value)
    return match.group(1) if match else None


def detect_context(parsed: ParsedEmail, auth: AuthenticationAnalysis,
                   trusted_domains: Iterable[str] = ()) -> MessageContext:
    trusted_domains = set(trusted_domains)
    markers: List[str] = []
    list_headers = [n for n in ("List-Id", "List-Post", "Mailing-List") if parsed.has(n)]
    precedence = (parsed.get_first("Precedence") or "").lower()
    if list_headers:
        markers.append("mailing-list headers: " + ", ".join(list_headers))
    if precedence == "list":
        markers.append("Precedence: list")
    forward_headers = [n for n in ("Resent-From", "Resent-Sender", "X-Forwarded-To",
                                   "X-Forwarded-For") if parsed.has(n)]
    # Receivers such as Gmail seal every incoming message themselves; only a
    # seal from an intermediary outside the trusted infrastructure indicates relaying.
    foreign_seals = [s for s in parsed.get_all("ARC-Seal")
                     if organizational_domain(_tag(s, "d")) not in trusted_domains]
    if foreign_seals:
        forward_headers.append("ARC-Seal")
    if forward_headers:
        markers.append("forwarding headers: " + ", ".join(forward_headers))
    bulk = parsed.has("List-Unsubscribe") or precedence == "bulk" or parsed.has("Feedback-ID")
    arc_pass = bool(auth.arc and auth.arc.status == "pass")
    if arc_pass:
        markers.append("trusted arc=pass")
    return MessageContext(
        mailing_list=bool(list_headers) or precedence == "list",
        forwarded=bool(forward_headers),
        bulk_sender=bulk,
        arc_pass=arc_pass,
        markers=markers,
    )


def _related(a: Optional[str], b: Optional[str]) -> bool:
    """Same organisation, or a known legitimate service relationship."""
    if same_organization(a, b):
        return True
    org_a, org_b = organizational_domain(a), organizational_domain(b)
    return KNOWN_RELATED_DOMAINS.get(org_a) == org_b or KNOWN_RELATED_DOMAINS.get(org_b) == org_a


def detect_findings(parsed: ParsedEmail, route: RouteAnalysis,
                    auth: AuthenticationAnalysis,
                    protected_domains: Iterable[str]) -> List[Finding]:
    protected = list(protected_domains)
    ctx = detect_context(parsed, auth, route.trusted_domains)
    findings: List[Finding] = []
    findings += _context_findings(ctx)
    findings += _authentication_findings(parsed, auth, ctx)
    findings += _sender_findings(parsed, ctx, protected)
    findings += _domain_findings(parsed, auth, protected)
    findings += _header_findings(parsed)
    findings += _route_findings(parsed, route)
    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    return findings


def _context_findings(ctx: MessageContext) -> List[Finding]:
    findings = []
    if ctx.mailing_list:
        findings.append(Finding(
            "CONTEXT-MAILING-LIST", "Message was distributed by a mailing list", "info",
            "context", ctx.markers,
            "Lists legitimately re-send mail from their own servers and often modify "
            "the subject/body, which breaks SPF and DKIM for the original author.",
            "List headers can be added by anyone; they mitigate, not excuse, failures."))
    if ctx.forwarded or ctx.arc_pass:
        findings.append(Finding(
            "CONTEXT-FORWARDED", "Message shows forwarding / ARC markers", "info",
            "context", ctx.markers,
            "Forwarders send from IPs not listed in the original sender's SPF record, "
            "so SPF failure is expected; ARC can carry the original results.",
            "ARC is only as trustworthy as the intermediaries that sealed it."))
    return findings


def _authentication_findings(parsed: ParsedEmail, auth: AuthenticationAnalysis,
                             ctx: MessageContext) -> List[Finding]:
    findings: List[Finding] = []
    relayed = ctx.mailing_list or ctx.forwarded or ctx.arc_pass
    mitigations = ctx.markers if relayed else []

    if auth.dmarc.status == "fail":
        policy = auth.dmarc.details.get("p")
        severity = "medium" if (relayed and ctx.arc_pass) else "high"
        evidence = [f"dmarc={auth.dmarc.raw_result} header.from={auth.dmarc.domain}"]
        if policy:
            evidence.append(f"published policy p={policy}")
        if auth.arc and auth.arc.details:
            evidence.append("ARC i=1 saw: " + ", ".join(
                f"{k[9:]}={v}" for k, v in auth.arc.details.items()))
        findings.append(Finding(
            "AUTH-DMARC-FAIL", "DMARC failed for the visible From domain", severity,
            "authentication", evidence,
            "DMARC ties the From address the recipient sees to a domain that passed "
            "SPF or DKIM. A failure means the From domain did not authorise this message.",
            "Mailing lists and forwarders can cause DMARC failures for genuine mail; "
            "the result is only as reliable as the receiving server that recorded it.",
            mitigations))

    if auth.spf.status == "fail":
        softfail = auth.spf.raw_result == "softfail"
        severity = "low" if (softfail or relayed) else "medium"
        findings.append(Finding(
            "AUTH-SPF-FAIL", f"SPF {auth.spf.raw_result} for the envelope sender",
            severity, "authentication",
            [f"spf={auth.spf.raw_result} smtp.mailfrom domain={auth.spf.domain}"]
            + ([f"receiver note: {auth.spf.details['comment']}"]
               if auth.spf.details.get("comment") else []),
            "The server that delivered the message is not authorised to send for the "
            "envelope-sender domain, which is consistent with spoofing.",
            "SPF checks the Return-Path domain, not the visible From. Forwarding "
            "breaks SPF for legitimate mail.", mitigations))

    if auth.dkim.status == "fail":
        findings.append(Finding(
            "AUTH-DKIM-FAIL", "DKIM signature failed verification",
            "low" if relayed else "medium", "authentication",
            [f"dkim={auth.dkim.raw_result} header.d={auth.dkim.domain}"]
            + ([f"reason: {auth.dkim.details['reason']}"]
               if "reason" in auth.dkim.details else []),
            "The message was altered after signing, or the signature was forged.",
            "Mailing-list footers, subject tags and some security gateways modify "
            "messages and break signatures.", mitigations))

    if (auth.dmarc.status in ("missing", "neutral")
            and (auth.spf.status == "pass" or auth.dkim_passing_domains)
            and auth.alignment.get("computed_dmarc_alignment") == "fail"
            and auth.alignment.get("from_domain")):
        findings.append(Finding(
            "AUTH-NOT-ALIGNED", "Authentication passed only for an unrelated domain",
            "medium", "authentication",
            [f"From domain: {auth.alignment['from_domain']}",
             f"SPF domain: {auth.alignment['spf_domain']} "
             f"(spf={auth.spf.raw_result})",
             f"DKIM pass domains: {', '.join(auth.alignment['dkim_domains']) or 'none'}"],
            "Passing SPF/DKIM proves only that *some* domain sent the message. If none "
            "of those domains matches the visible From, the From address is unverified.",
            "Computed by this tool with an approximate organisational-domain rule; "
            "legitimate third-party senders sometimes lack aligned DKIM.",
            mitigations))

    if not auth.any_trusted:
        findings.append(Finding(
            "AUTH-MISSING", "No trusted authentication results", "low",
            "authentication",
            [f"{len(parsed.authentication_results)} Authentication-Results header(s), "
             f"{len(auth.untrusted_results)} untrusted result(s)"] + auth.assumptions,
            "Without trusted SPF/DKIM/DMARC results the sender identity cannot be "
            "checked from the headers.",
            "Internal mail and some servers record no results. Obtain the headers "
            "from the recipient's own mailbox server where possible."))

    trusted_pass = {r.method for r in auth.results if r.trusted and r.result == "pass"}
    forged = [r for r in auth.untrusted_results
              if r.result == "pass" and r.method in ("spf", "dkim", "dmarc")
              and r.method not in trusted_pass]
    if forged and auth.any_trusted:
        findings.append(Finding(
            "AUTH-UNTRUSTED-CLAIMS",
            "Untrusted headers claim authentication passes the trusted server did not record",
            "medium", "authentication",
            [f"{r.method}={r.result} claimed by '{r.authserv_id or 'unknown'}' "
             f"(header #{r.header_index + 1})" for r in forged],
            "Attackers insert fake Authentication-Results headers hoping a person or "
            "a naive tool will read them instead of the receiving server's verdict.",
            "Some multi-stage gateways legitimately add their own headers; confirm the "
            "trusted authserv-id list is complete."))
    return findings


def _sender_findings(parsed: ParsedEmail, ctx: MessageContext,
                     protected: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    if not parsed.from_addrs:
        return findings
    sender = parsed.from_addrs[0]
    from_domain = sender.domain

    reply_domains = [a.domain for a in parsed.reply_to if a.domain]
    unrelated_reply = [d for d in reply_domains if not _related(from_domain, d)]
    if from_domain and unrelated_reply:
        freemail = [d for d in unrelated_reply if is_freemail(d)]
        severity = "low" if (ctx.mailing_list or ctx.bulk_sender) and not freemail else "medium"
        findings.append(Finding(
            "SENDER-REPLYTO-MISMATCH", "Reply-To points to a different organisation",
            severity, "sender",
            [f"From: {sanitize_for_display(str(sender), 300)}",
             "Reply-To: " + ", ".join(sanitize_for_display(str(a), 300)
                                      for a in parsed.reply_to)]
            + ([f"Reply-To uses a free webmail provider: {', '.join(freemail)}"]
               if freemail else []),
            "Replies would go to someone other than the apparent sender, a common "
            "pattern in business-email-compromise and phishing.",
            "Newsletters, ticketing systems and mailing lists legitimately set a "
            "different Reply-To.", ctx.markers if severity == "low" else []))

    rp = parsed.return_path
    if from_domain and rp and rp.domain and not _related(from_domain, rp.domain):
        findings.append(Finding(
            "SENDER-RETURNPATH-MISMATCH",
            "Envelope sender (Return-Path) belongs to a different organisation", "low",
            "sender",
            [f"From domain: {from_domain}", f"Return-Path: <{rp.address}>"],
            "SPF authenticates the Return-Path domain, so a mismatch means a pass "
            "for SPF does not vouch for the visible sender.",
            "Very common for legitimate bulk mail sent through e-mail service "
            "providers (bounce handling)."))

    display = sender.display_name
    embedded = [d.lower() for d in _EMAIL_IN_TEXT_RE.findall(display)]
    mismatched = [d for d in embedded if not same_organization(d, from_domain)]
    if mismatched:
        findings.append(Finding(
            "SENDER-DISPLAYNAME-ADDRESS",
            "Display name contains a different e-mail address", "high", "sender",
            [f"From: {sanitize_for_display(str(sender), 300)}",
             f"Display name shows domain(s) {', '.join(mismatched)}, "
             f"actual address domain is {from_domain}"],
            "Many mail clients show only the display name, so the recipient sees the "
            "embedded address instead of the real one.",
            "Rarely legitimate; some forwarding services write 'x@y via Service'."))
    elif display and from_domain:
        words = set(re.findall(r"[a-z0-9]+", display.lower()))
        for target in protected:
            label = registrable_label(target)
            if len(label) >= 4 and label in words and not _related(from_domain, target):
                freemail = is_freemail(from_domain)
                findings.append(Finding(
                    "SENDER-DISPLAYNAME-BRAND",
                    f"Display name invokes '{label}' but the address is not on {target}",
                    "high" if freemail else "medium", "sender",
                    [f"From: {sanitize_for_display(str(sender), 300)}"]
                    + (["Sending address is a free webmail account."] if freemail else []),
                    "Brand impersonation relies on recipients trusting the display name.",
                    "Legitimate partners and resellers sometimes mention a brand in "
                    "their sender name; protected-brand list is not exhaustive."))
                break
    return findings


def _domain_findings(parsed: ParsedEmail, auth: AuthenticationAnalysis,
                     protected: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    from_domain = parsed.from_domain
    candidates = []
    for label, addrs in (("From", parsed.from_addrs), ("Reply-To", parsed.reply_to),
                         ("Sender", parsed.sender)):
        candidates += [(label, a.domain) for a in addrs if a.domain]
    if parsed.return_path and parsed.return_path.domain:
        candidates.append(("Return-Path", parsed.return_path.domain))
    candidates += [("DKIM d=", d) for d in auth.dkim_passing_domains]

    reported = set()
    for field_name, domain in candidates:
        for match in check_lookalike(domain, protected):
            key = (domain, match.resembles)
            if key in reported:
                continue
            reported.add(key)
            weak = match.technique == "suffix-swap"
            severity = "low" if weak else (
                "high" if field_name in ("From", "Reply-To", "Sender") else "medium")
            findings.append(Finding(
                "DOMAIN-LOOKALIKE",
                f"{field_name} domain resembles {match.resembles} ({match.technique})",
                severity, "domain",
                [f"{field_name}: {domain}", match.detail],
                "Look-alike domains are registered so that a hurried reader mistakes "
                "them for a trusted organisation. Authentication can fully pass for "
                "them because the attacker owns the domain.",
                "Similarity is heuristic; a protected organisation may own the "
                "look-alike (defensive registration)."))

    for field_name, addrs in (("Reply-To", parsed.reply_to),
                              ("Return-Path", [parsed.return_path] if parsed.return_path else [])):
        for addr in addrs:
            match = compare_related_domains(from_domain, addr.domain)
            if match:
                findings.append(Finding(
                    "DOMAIN-INTERNAL-LOOKALIKE",
                    f"{field_name} domain is a near copy of the From domain", "high",
                    "domain",
                    [f"From domain: {from_domain}", f"{field_name}: {addr.domain}",
                     match.detail],
                    "Replies or bounces are diverted to a domain that looks identical "
                    "to the sender's, typical of invoice-fraud / BEC.",
                    "Short or generic domain names can be similar by coincidence."))

    msgid = parsed.message_id_domain
    if msgid and from_domain and not _related(msgid, from_domain) \
            and not any(_related(msgid, d) for d in auth.dkim_passing_domains):
        findings.append(Finding(
            "MSGID-DOMAIN-MISMATCH", "Message-ID domain unrelated to the From domain",
            "info", "header", [f"Message-ID domain: {msgid}", f"From domain: {from_domain}"],
            "The Message-ID is usually generated by the sender's own mail system.",
            "Weak indicator: hosted mail, ESPs and many clients use their own "
            "Message-ID domain."))
    return findings


def _header_findings(parsed: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []
    grouped = {"duplicate": [], "missing": [], "malformed": []}
    for issue in parsed.issues:
        if issue.kind in grouped and issue.severity != "info":
            grouped[issue.kind].append(issue)
    meta = {
        "duplicate": ("HEADER-DUPLICATE", "Header fields that must be unique are repeated",
                      "Duplicate From/Subject/Date headers can make different clients and "
                      "filters see different senders - a known filter-evasion trick.",
                      "Rarely caused by broken software; still unusual."),
        "missing": ("HEADER-MISSING", "Required or expected header fields are missing",
                    "Missing fields reduce what can be verified and are typical of "
                    "hand-crafted or bulk-spam messages.",
                    "Partially pasted headers will also appear to be missing fields."),
        "malformed": ("HEADER-MALFORMED", "Header fields are malformed",
                      "Malformed fields can indicate hand-crafted messages or attempts "
                      "to confuse parsers, and they limit confidence in the analysis.",
                      "Old or buggy mail software also produces malformed headers."),
    }
    for kind, issues in grouped.items():
        if not issues:
            continue
        rule_id, title, why, limits = meta[kind]
        severity = max((i.severity for i in issues), key=lambda s: SEVERITY_ORDER[s])
        findings.append(Finding(
            rule_id, title, severity, "header",
            [f"{i.field}: {i.detail}" for i in issues], why, limits))
    return findings


def _route_findings(parsed: ParsedEmail, route: RouteAnalysis) -> List[Finding]:
    findings: List[Finding] = []
    inconsistent = [a for a in route.anomalies
                    if a.kind in ("time-reversal", "date-after-delivery",
                                  "future-timestamp", "future-date",
                                  "date-long-before-route")]
    if inconsistent:
        severity = max((a.severity for a in inconsistent), key=lambda s: SEVERITY_ORDER[s])
        findings.append(Finding(
            "ROUTE-INCONSISTENT", "Delivery route timestamps are inconsistent", severity,
            "route", [a.detail for a in inconsistent],
            "Forged Received headers inserted by a sender are often written by hand "
            "and do not line up with the hops added by real servers.",
            "Misconfigured server clocks cause the same symptoms; only hops below the "
            "trust boundary can be forged by the sender."))
    if any(a.kind == "missing-route" for a in route.anomalies) and not parsed.headers_only:
        findings.append(Finding(
            "ROUTE-MISSING", "No Received headers - route cannot be reconstructed", "low",
            "route", ["0 Received headers in a complete message"],
            "Every message delivered over SMTP gains Received headers; their absence "
            "suggests the headers were stripped or the file was fabricated.",
            "Messages exported from some clients or drafts may lack them."))
    return findings
