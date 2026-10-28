"""Generate the synthetic labelled dataset (dataset/emails/*.eml + test_cases.csv).

Every scenario is labelled here, by its design, *before* the detector is run.
The split column assigns cases to a tuning set (used to choose the scoring
approach) and a held-out test set (used only for the final metrics).

All messages are synthetic.  The recipient organisation is the fictitious
"uni-example.edu"; brand names appear only to model impersonation.  Run:

    python dataset/generate_dataset.py
"""

from __future__ import annotations

import csv
import hashlib
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "emails"
BASE_TIME = datetime(2026, 9, 14, 9, 30, 0, tzinfo=timezone.utc)
RECIPIENT = "student@uni-example.edu"
MX = "mx1.uni-example.edu"
MAILBOX = "mailbox01.uni-example.edu"


def ts(minutes: float) -> str:
    return format_datetime(BASE_TIME + timedelta(minutes=minutes))


def build(*, sender, subject, sending_hops, auth, from_display="", reply_to=None,
          return_path=None, message_id=None, date_offset=-1.0, extra=(),
          extra_auth_headers=(), arc=None, to=RECIPIENT, omit=(), duplicate=(),
          body="Hello,\n\nPlease see the message below.\n\nRegards\n",
          internal_only=False):
    """Assemble a raw message.

    sending_hops: list of (helo, rdns, ip, by_host, minutes) in delivery order,
    ending at the hop that hands the message to the recipient's MX.
    auth: the Authentication-Results payload recorded by mx1.uni-example.edu.
    """
    domain = sender.rpartition("@")[2]
    last_t = sending_hops[-1][4] if sending_hops else 0
    headers = []
    headers.append(("Received", f"from {MX} ({MX} [10.20.0.11]) by {MAILBOX} "
                                f"with LMTP id 8F2A1C; {ts(last_t + 0.2)}"))
    if auth is not None:
        headers.append(("Authentication-Results", f"{MX};\r\n\t{auth}"))
    if arc:
        headers.append(("ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=forwarder.example; s=arc; b=AbC="))
        headers.append(("ARC-Authentication-Results", f"i=1; forwarder.example; {arc}"))
    for name, value in extra_auth_headers:
        headers.append((name, value))
    for helo, rdns, ip, by_host, minutes in reversed(sending_hops):
        rdns_part = f"{rdns} " if rdns else "unknown "
        headers.append(("Received",
                        f"from {helo} ({rdns_part}[{ip}])\r\n\tby {by_host} with ESMTPS "
                        f"id {stable_id(helo, minutes):08d}\r\n\tfor <{to}>; {ts(minutes)}"))
    if internal_only:
        headers = [h for h in headers if h[0] != "Authentication-Results"]
    # return_path="" models the null reverse-path used by bounces/auto-replies.
    headers.append(("Return-Path", f"<{sender if return_path is None else return_path}>"))
    headers.append(("From", f'"{from_display}" <{sender}>' if from_display else f"<{sender}>"))
    headers.append(("To", f"<{to}>"))
    if reply_to:
        headers.append(("Reply-To", reply_to))
    headers.append(("Subject", subject))
    headers.append(("Date", ts((sending_hops[0][4] if sending_hops else 0) + date_offset)))
    headers.append(("Message-ID", message_id or f"<{stable_id(subject, digits=12)}.{stable_id(sender, digits=6)}@{domain}>"))
    headers.append(("MIME-Version", "1.0"))
    headers.append(("Content-Type", "text/plain; charset=utf-8"))
    headers.extend(extra)
    for name in duplicate:
        value = next(v for n, v in headers if n == name)
        headers.append((name, value.replace("<", "<alt-", 1) if name == "From" else value))
    headers = [h for h in headers if h[0] not in omit]
    text = "".join(f"{n}: {v}\r\n" for n, v in headers) + "\r\n" + body.replace("\n", "\r\n")
    return text.encode("utf-8")


def stable_id(*parts, digits=8) -> int:
    """Deterministic pseudo-random id (built-in hash() is salted per process)."""
    digest = hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()
    return int(digest, 16) % 10 ** digits


def hop(helo, ip, minutes, by=MX, rdns=None):
    return (helo, rdns if rdns is not None else helo, ip, by, minutes)


GMAIL_HOPS = [hop("mail-sor-f41.google.com", "209.85.220.41", 0)]
OUTLOOK_HOPS = [hop("EUR05-AM6-obe.outbound.protection.outlook.com", "40.107.22.98", 0)]

CASES = []


def case(name, label, category, description, raw):
    CASES.append((name, label, category, description, raw))


# ---------------------------------------------------------------- legitimate
case("L01_personal_gmail", "legitimate", "normal",
     "Personal Gmail message, all authentication aligned and passing.",
     build(sender="ayesha.khan@gmail.com", from_display="Ayesha Khan",
           subject="Notes from today's lab", sending_hops=GMAIL_HOPS,
           message_id="<CAF3x9k2Lm@mail.gmail.com>",
           auth="spf=pass smtp.mailfrom=ayesha.khan@gmail.com; "
                "dkim=pass header.d=gmail.com header.s=20230601; "
                "dmarc=pass (p=NONE) header.from=gmail.com"))
case("L02_github_notification", "legitimate", "normal",
     "GitHub notification sent from GitHub's own infrastructure.",
     build(sender="notifications@github.com", from_display="GitHub",
           subject="[uni-example/df-lab] New issue opened (#42)",
           return_path="noreply@bounces.github.com",
           sending_hops=[hop("out-21.smtp.github.com", "192.30.252.204", 0)],
           extra=[("List-Unsubscribe", "<mailto:unsub@reply.github.com>")],
           auth="spf=pass smtp.mailfrom=bounces.github.com; "
                "dkim=pass header.d=github.com header.s=pf2023; "
                "dmarc=pass (p=REJECT) header.from=github.com"))
case("L03_internal_department", "legitimate", "normal",
     "Department announcement relayed inside the university.",
     build(sender="hod.cs@uni-example.edu", from_display="Head of CS",
           subject="Midterm schedule", sending_hops=[
               hop("staffmail.uni-example.edu", "10.20.4.7", 0)],
           auth="spf=pass smtp.mailfrom=uni-example.edu; "
                "dkim=pass header.d=uni-example.edu; "
                "dmarc=pass header.from=uni-example.edu"))
case("L04_bank_statement", "legitimate", "normal",
     "Bank e-statement notice with aligned DKIM and SPF.",
     build(sender="estatements@example-bank.com", from_display="Example Bank",
           subject="Your September statement is ready",
           sending_hops=[hop("mta2.example-bank.com", "154.57.33.12", 0)],
           auth="spf=pass smtp.mailfrom=example-bank.com; "
                "dkim=pass header.d=example-bank.com; "
                "dmarc=pass (p=REJECT) header.from=example-bank.com"))
case("L05_esp_newsletter", "legitimate", "normal",
     "Retail newsletter sent through an ESP: Return-Path on the ESP domain, "
     "DKIM aligned with the brand.",
     build(sender="news@shop-example.com", from_display="Shop Example",
           subject="Autumn sale starts now", return_path="bounce-77@em.esp-mailer.net",
           sending_hops=[hop("o1.em.esp-mailer.net", "167.89.12.44", 0)],
           extra=[("List-Unsubscribe", "<https://shop-example.com/u/77>"),
                  ("Feedback-ID", "77:esp")],
           auth="spf=pass smtp.mailfrom=em.esp-mailer.net; "
                "dkim=pass header.d=shop-example.com; dkim=pass header.d=esp-mailer.net; "
                "dmarc=pass (p=QUARANTINE) header.from=shop-example.com"))
case("L06_helpdesk_ticket", "legitimate", "normal",
     "Vendor support ticket; Reply-To points at the vendor's hosted helpdesk domain.",
     build(sender="support@softvendor.com", from_display="SoftVendor Support",
           reply_to="<support+id8812@softvendor.helpdesk-cloud.com>",
           subject="[Ticket #8812] Licence activation",
           sending_hops=[hop("mail.helpdesk-cloud.com", "52.4.18.9", 0)],
           return_path="bounce@helpdesk-cloud.com",
           auth="spf=pass smtp.mailfrom=helpdesk-cloud.com; "
                "dkim=pass header.d=softvendor.com; "
                "dmarc=pass header.from=softvendor.com"))
case("L07_mailing_list_rewritten", "legitimate", "mailing-list",
     "Mailing list that rewrites From to its own domain (DMARC mitigation).",
     build(sender="df-discuss@lists.uni-example.org",
           from_display="Bilal Ahmed via df-discuss",
           reply_to="<bilal.ahmed@forensics-lab.org>",
           subject="[df-discuss] Volatility plugin question",
           sending_hops=[hop("lists.uni-example.org", "128.30.2.5", 0)],
           return_path="df-discuss-bounces@lists.uni-example.org",
           extra=[("List-Id", "<df-discuss.lists.uni-example.org>"),
                  ("List-Unsubscribe", "<mailto:df-discuss-leave@lists.uni-example.org>"),
                  ("Precedence", "list")],
           auth="spf=pass smtp.mailfrom=lists.uni-example.org; "
                "dkim=pass header.d=lists.uni-example.org; "
                "dmarc=pass header.from=lists.uni-example.org"))
case("L08_mailing_list_dkim_broken", "legitimate", "mailing-list",
     "Mailing list that keeps the author's From and adds a footer: DKIM and "
     "DMARC fail for the author's domain, ARC passes.",
     build(sender="sara.malik@author-corp.com", from_display="Sara Malik",
           subject="[sec-list] Incident write-up",
           sending_hops=[hop("mail.author-corp.com", "81.2.69.160", -2, by="lists.sec-list.org"),
                         hop("lists.sec-list.org", "128.30.9.17", 0)],
           return_path="sec-list-bounces@sec-list.org",
           extra=[("List-Id", "<sec-list.sec-list.org>"), ("Precedence", "list")],
           arc="spf=pass smtp.mailfrom=author-corp.com; dkim=pass header.d=author-corp.com; "
               "dmarc=pass header.from=author-corp.com",
           auth="spf=pass smtp.mailfrom=sec-list.org; "
                "dkim=fail (body hash did not verify) header.d=author-corp.com; "
                "dmarc=fail (p=NONE) header.from=author-corp.com; arc=pass"))
case("L09_forwarded_spf_fail", "legitimate", "forwarded",
     "Alumni forwarding service: SPF fails at the final hop, DKIM survives and aligns.",
     build(sender="omar.farooq@outlook.com", from_display="Omar Farooq",
           subject="Reunion photos",
           sending_hops=[
               hop("EUR05-AM6-obe.outbound.protection.outlook.com", "40.107.22.98", -1,
                   by="mx.alumni-forward.org"),
               hop("relay.alumni-forward.org", "64.62.200.3", 0)],
           extra=[("X-Forwarded-To", RECIPIENT)],
           auth="spf=fail smtp.mailfrom=outlook.com; "
                "dkim=pass header.d=outlook.com; dmarc=pass header.from=outlook.com"))
case("L10_forwarded_softfail_arc", "legitimate", "forwarded",
     "Forwarded via a personal domain with SPF softfail; ARC records the original pass.",
     build(sender="prof.rahman@research-inst.org", from_display="Dr. Rahman",
           subject="Re: thesis draft",
           sending_hops=[hop("smtp.research-inst.org", "193.60.10.4", -1, by="mx.forwarder.example"),
                         hop("out.forwarder.example", "89.187.162.1", 0)],
           arc="spf=pass smtp.mailfrom=research-inst.org; dkim=pass header.d=research-inst.org",
           auth="spf=softfail smtp.mailfrom=research-inst.org; "
                "dkim=pass header.d=research-inst.org; "
                "dmarc=pass header.from=research-inst.org; arc=pass"))
case("L11_forwarded_everything_broken", "legitimate", "forwarded",
     "Forwarder that rewrites the body: SPF, DKIM and DMARC all fail; "
     "only ARC shows the original passes.",
     build(sender="hr@partner-company.com", from_display="Partner HR",
           subject="Internship offer letter",
           sending_hops=[hop("mx.partner-company.com", "62.24.135.9", -1, by="mx.forwarder.example"),
                         hop("out.forwarder.example", "89.187.162.1", 0)],
           arc="spf=pass smtp.mailfrom=partner-company.com; dkim=pass header.d=partner-company.com; "
               "dmarc=pass header.from=partner-company.com",
           extra=[("Resent-From", "<careers-forward@forwarder.example>")],
           auth="spf=fail smtp.mailfrom=partner-company.com; "
                "dkim=fail (signature verification failed) header.d=partner-company.com; "
                "dmarc=fail (p=QUARANTINE) header.from=partner-company.com; arc=pass"))
case("L12_microsoft365_style", "legitimate", "normal",
     "Message whose top Authentication-Results lacks an authserv-id (Microsoft 365 style).",
     build(sender="registrar@college-example.ac.uk", from_display="Registrar",
           subject="Exchange programme confirmation", sending_hops=OUTLOOK_HOPS,
           auth=None,
           extra_auth_headers=[("Authentication-Results",
                                "spf=pass (sender IP is 40.107.22.98) "
                                "smtp.mailfrom=college-example.ac.uk; dkim=pass "
                                "(signature was verified) header.d=college-example.ac.uk;"
                                "dmarc=pass action=none header.from=college-example.ac.uk;"
                                "compauth=pass reason=100")]))
case("L13_calendar_invite", "legitimate", "normal",
     "Colleague's meeting invite, all aligned.",
     build(sender="t.hussain@uni-example.edu", from_display="Tariq Hussain",
           subject="Invitation: Project viva @ Thu 2pm",
           sending_hops=[hop("staffmail.uni-example.edu", "10.20.4.8", 0)],
           auth="spf=pass smtp.mailfrom=uni-example.edu; dkim=pass header.d=uni-example.edu; "
                "dmarc=pass header.from=uni-example.edu"))
case("L14_amazon_ses", "legitimate", "normal",
     "Genuine Amazon shipping notice via amazonses.com envelope sender.",
     build(sender="shipment-tracking@amazon.com", from_display="Amazon.com",
           subject="Your package has shipped", return_path="0100018a@amazonses.com",
           sending_hops=[hop("a8-31.smtp-out.amazonses.com", "54.240.8.31", 0)],
           auth="spf=pass smtp.mailfrom=amazonses.com; dkim=pass header.d=amazon.com; "
                "dkim=pass header.d=amazonses.com; dmarc=pass (p=QUARANTINE) header.from=amazon.com"))
case("L15_paypal_genuine", "legitimate", "normal",
     "Genuine PayPal receipt with display name 'PayPal'.",
     build(sender="service@paypal.com", from_display="PayPal",
           subject="Receipt for your payment",
           sending_hops=[hop("mx0.slc.paypal.com", "173.0.84.226", 0)],
           auth="spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; "
                "dmarc=pass (p=REJECT) header.from=paypal.com"))
case("L16_small_business_no_dmarc", "legitimate", "normal",
     "Small business without DKIM or DMARC; SPF passes.",
     build(sender="orders@printshop-lahore.com", from_display="Print Shop",
           subject="Your order is ready for pickup",
           sending_hops=[hop("mail.printshop-lahore.com", "203.99.48.21", 0)],
           auth="spf=pass smtp.mailfrom=printshop-lahore.com; dkim=none; "
                "dmarc=none header.from=printshop-lahore.com"))
case("L17_queued_delivery", "legitimate", "normal",
     "Legitimate message delayed 26 hours in a queue.",
     build(sender="it-alerts@campus-services.org", from_display="Campus IT",
           subject="Scheduled maintenance",
           sending_hops=[hop("smtp1.campus-services.org", "10.1.1.5", -1560,
                             by="gw.campus-services.org"),
                         hop("gw.campus-services.org", "131.107.1.20", 0)],
           auth="spf=pass smtp.mailfrom=campus-services.org; "
                "dkim=pass header.d=campus-services.org; dmarc=pass header.from=campus-services.org"))
case("L18_custom_domain_via_gmail", "legitimate", "normal",
     "Custom domain hosted on Google Workspace; Message-ID on mail.gmail.com.",
     build(sender="hello@startup-example.io", from_display="Startup Example",
           subject="Interview availability", sending_hops=GMAIL_HOPS,
           message_id="<CAJx7_Uk@mail.gmail.com>",
           auth="spf=pass smtp.mailfrom=startup-example.io; "
                "dkim=pass header.d=startup-example.io; dmarc=pass header.from=startup-example.io"))
case("L19_clock_skew", "legitimate", "normal",
     "Legitimate message whose internal relay clock is 3 minutes fast (within tolerance).",
     build(sender="library@uni-example.edu", from_display="University Library",
           subject="Book due reminder",
           sending_hops=[hop("ils.uni-example.edu", "10.20.9.2", 3, by="relay.uni-example.edu"),
                         hop("relay.uni-example.edu", "10.20.0.3", 0)],
           auth="spf=pass smtp.mailfrom=uni-example.edu; dkim=pass header.d=uni-example.edu; "
                "dmarc=pass header.from=uni-example.edu"))
case("L20_autoreply_null_sender", "legitimate", "normal",
     "Out-of-office auto-reply with a null Return-Path.",
     build(sender="dean@uni-example.edu", from_display="Dean",
           subject="Automatic reply: Request", return_path="",
           sending_hops=[hop("staffmail.uni-example.edu", "10.20.4.7", 0)],
           extra=[("Auto-Submitted", "auto-replied")],
           auth="spf=none smtp.helo=staffmail.uni-example.edu; dkim=pass header.d=uni-example.edu; "
                "dmarc=pass header.from=uni-example.edu"))
case("L21_internal_scanner", "legitimate", "malformed",
     "Old network scanner on the internal network: no Message-ID, no auth results.",
     build(sender="scanner@uni-example.edu", subject="Scanned document",
           sending_hops=[hop("printer-3f", "10.20.33.4", 0, rdns="")],
           omit=("Message-ID",), auth=None, internal_only=True))

# ---------------------------------------------------------------- suspicious
case("S01_lookalike_digit", "suspicious", "lookalike",
     "paypa1.com look-alike; attacker owns the domain so SPF/DKIM/DMARC pass.",
     build(sender="service@paypa1.com", from_display="PayPal",
           subject="Your account has been limited",
           sending_hops=[hop("mail.paypa1.com", "45.137.21.9", 0)],
           auth="spf=pass smtp.mailfrom=paypa1.com; dkim=pass header.d=paypa1.com; "
                "dmarc=pass header.from=paypa1.com"))
case("S02_displayname_brand_freemail", "suspicious", "sender-spoofing",
     "'PayPal Security' display name on a Gmail account.",
     build(sender="paypal.security.team2026@gmail.com", from_display="PayPal Security",
           subject="Unusual sign-in detected", sending_hops=GMAIL_HOPS,
           message_id="<CAB2k@mail.gmail.com>",
           auth="spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; "
                "dmarc=pass header.from=gmail.com"))
case("S03_exact_domain_spoof", "suspicious", "auth-failure",
     "From forges the university's own domain from an external server.",
     build(sender="vc.office@uni-example.edu", from_display="Vice Chancellor",
           subject="Urgent: gift card request",
           sending_hops=[hop("vps-338.hostingco.net", "185.220.101.47", 0)],
           auth="spf=fail smtp.mailfrom=uni-example.edu; dkim=none; "
                "dmarc=fail (p=REJECT) header.from=uni-example.edu"))
case("S04_bec_freemail_replyto", "suspicious", "sender-spoofing",
     "Spoofed partner address with Reply-To on Gmail; SPF softfail, DMARC fail (p=none).",
     build(sender="accounts@partner-corp.com", from_display="Partner Corp Accounts",
           reply_to="<partnercorp.payments@gmail.com>",
           subject="Updated bank details for invoice 4471",
           sending_hops=[hop("mail.cheap-smtp.biz", "91.215.85.12", 0)],
           return_path="bounce@cheap-smtp.biz",
           auth="spf=softfail smtp.mailfrom=cheap-smtp.biz; dkim=none; "
                "dmarc=fail (p=NONE) header.from=partner-corp.com"))
case("S05_bec_lookalike_replyto", "suspicious", "lookalike",
     "Real supplier address, but Reply-To uses a near-identical domain.",
     build(sender="john@acme-supplies.com", from_display="John (Acme Supplies)",
           reply_to="<john@acme-suppiies.com>",
           subject="RE: payment schedule",
           sending_hops=[hop("mail.acme-supplies.com", "37.120.55.4", 0)],
           auth="spf=pass smtp.mailfrom=acme-supplies.com; dkim=pass header.d=acme-supplies.com; "
                "dmarc=pass header.from=acme-supplies.com"))
case("S06_idn_homograph", "suspicious", "lookalike",
     "Cyrillic 'а' in pаypal.com (punycode xn--pypal-4ve.com).",
     build(sender="security@xn--pypal-4ve.com", from_display="PayPal",
           subject="Verify your identity",
           sending_hops=[hop("mx.xn--pypal-4ve.com", "45.137.22.15", 0)],
           auth="spf=pass smtp.mailfrom=xn--pypal-4ve.com; dkim=pass header.d=xn--pypal-4ve.com; "
                "dmarc=pass header.from=xn--pypal-4ve.com"))
case("S07_brand_embedded", "suspicious", "lookalike",
     "paypal-account-verify.com, a newly registered brand-embedding domain.",
     build(sender="no-reply@paypal-account-verify.com", from_display="PayPal Service",
           subject="Action required",
           sending_hops=[hop("smtp.paypal-account-verify.com", "45.141.84.2", 0)],
           auth="spf=pass smtp.mailfrom=paypal-account-verify.com; "
                "dkim=pass header.d=paypal-account-verify.com; dmarc=none"))
case("S08_brand_in_subdomain", "suspicious", "lookalike",
     "microsoft.com used as a sub-domain of secure-login-portal.net.",
     build(sender="alerts@microsoft.com.secure-login-portal.net",
           from_display="Microsoft Account Team",
           subject="Password expires today",
           sending_hops=[hop("mx.secure-login-portal.net", "193.42.33.8", 0)],
           auth="spf=pass smtp.mailfrom=secure-login-portal.net; "
                "dkim=pass header.d=secure-login-portal.net; dmarc=none"))
case("S09_displayname_address", "suspicious", "sender-spoofing",
     "Display name contains support@apple.com; real address on another domain.",
     build(sender="xk2@mailer-random.ru", from_display="support@apple.com",
           subject="Your Apple ID was locked",
           sending_hops=[hop("mailer-random.ru", "95.163.22.4", 0)],
           auth="spf=pass smtp.mailfrom=mailer-random.ru; dkim=none; "
                "dmarc=none header.from=mailer-random.ru"))
case("S10_duplicate_from", "suspicious", "malformed",
     "Two From headers so different clients show different senders.",
     build(sender="it-support@uni-example.edu", from_display="IT Support",
           subject="Mailbox quota exceeded",
           sending_hops=[hop("smtp.bulk-host.xyz", "185.81.157.3", 0)],
           duplicate=("From",), return_path="x@bulk-host.xyz",
           auth="spf=pass smtp.mailfrom=bulk-host.xyz; dkim=none; "
                "dmarc=fail (p=REJECT) header.from=uni-example.edu"))
case("S11_forged_auth_results", "suspicious", "auth-failure",
     "Attacker inserted a fake 'mx.google.com' Authentication-Results claiming passes.",
     build(sender="alerts@example-bank.com", from_display="Example Bank",
           subject="Confirm your card",
           sending_hops=[hop("srv1.vps-cheap.top", "176.97.210.4", 0)],
           extra_auth_headers=[("Authentication-Results",
                                "mx.google.com; spf=pass smtp.mailfrom=example-bank.com; "
                                "dkim=pass header.d=example-bank.com; dmarc=pass header.from=example-bank.com")],
           return_path="bounce@vps-cheap.top",
           auth="spf=fail smtp.mailfrom=vps-cheap.top; dkim=none; "
                "dmarc=fail (p=REJECT) header.from=example-bank.com"))
case("S12_forged_received_chain", "suspicious", "route",
     "Fabricated earlier Received hops with impossible timestamps; Date after delivery.",
     build(sender="hr@uni-example.edu", from_display="HR Department",
           subject="Salary revision letter",
           sending_hops=[hop("mail.uni-example.edu", "10.20.1.1", 180, by="smtp.uni-example.edu.relay-x.net"),
                         hop("smtp.relay-x.net", "141.98.10.60", 0)],
           date_offset=240, return_path="hr@relay-x.net",
           auth="spf=pass smtp.mailfrom=relay-x.net; dkim=none; "
                "dmarc=fail (p=QUARANTINE) header.from=uni-example.edu"))
case("S13_spf_dmarc_fail_bank", "suspicious", "auth-failure",
     "Bank spoof: SPF fail, DMARC fail, Return-Path on unrelated domain.",
     build(sender="security@example-bank.com", from_display="Example Bank Security",
           subject="Suspicious transaction", return_path="mailer@bulkmail-srv.com",
           sending_hops=[hop("bulkmail-srv.com", "103.153.79.2", 0)],
           auth="spf=fail smtp.mailfrom=bulkmail-srv.com; dkim=none; "
                "dmarc=fail (p=REJECT) header.from=example-bank.com"))
case("S14_dkim_fail_courier", "suspicious", "auth-failure",
     "Courier spoof with a broken (forged) DKIM signature and DMARC fail.",
     build(sender="delivery@dhl.com", from_display="DHL Express",
           subject="Parcel held at customs",
           sending_hops=[hop("smtp.parcel-notify.click", "5.181.86.10", 0)],
           return_path="n@parcel-notify.click",
           auth="spf=fail smtp.mailfrom=parcel-notify.click; "
                "dkim=fail (signature did not verify) header.d=dhl.com; "
                "dmarc=fail (p=REJECT) header.from=dhl.com"))
case("S15_unaligned_no_dmarc_recorded", "suspicious", "auth-failure",
     "SPF and DKIM pass only for a bulk sender; From claims netflix.com; receiver "
     "recorded no DMARC result.",
     build(sender="info@netflix.com", from_display="Netflix",
           subject="Payment declined - update details",
           return_path="bounce@bulk-sender-xyz.com",
           sending_hops=[hop("out.bulk-sender-xyz.com", "45.95.147.20", 0)],
           auth="spf=pass smtp.mailfrom=bulk-sender-xyz.com; "
                "dkim=pass header.d=bulk-sender-xyz.com"))
case("S16_typosquat", "suspicious", "lookalike",
     "dropboxx.com typosquat sharing a 'document'.",
     build(sender="share@dropboxx.com", from_display="Dropbox",
           subject="Ali shared 'Invoice.pdf' with you",
           sending_hops=[hop("mail.dropboxx.com", "45.153.160.2", 0)],
           auth="spf=pass smtp.mailfrom=dropboxx.com; dkim=pass header.d=dropboxx.com; "
                "dmarc=none header.from=dropboxx.com"))
case("S17_handcrafted_malformed", "suspicious", "malformed",
     "Hand-crafted message: no Date, malformed Message-ID, no auth results, no route.",
     b"From: Accounts Dept <accounts@uni-example.edu>\r\nTo: student@uni-example.edu\r\n"
     b"Subject: Fee refund\r\nMessage-ID: refund-2026\r\n"
     b"Reply-To: refunds.office@protonmail.com\r\n\r\nClick here.\r\n")
case("S18_compromised_account", "suspicious", "compromised",
     "Phishing from a genuinely compromised partner account: every header check passes "
     "(expected to be missed by header analysis).",
     build(sender="m.iqbal@partner-university.edu", from_display="Dr. M. Iqbal",
           subject="Shared folder: research grant documents",
           sending_hops=[hop("smtp.partner-university.edu", "128.2.42.10", 0)],
           auth="spf=pass smtp.mailfrom=partner-university.edu; "
                "dkim=pass header.d=partner-university.edu; dmarc=pass header.from=partner-university.edu"))
case("S19_org_lookalike", "suspicious", "lookalike",
     "Look-alike of the university's own domain (uni-examp1e.edu).",
     build(sender="it-helpdesk@uni-examp1e.edu", from_display="IT Helpdesk",
           subject="Re-validate your student account",
           sending_hops=[hop("mail.uni-examp1e.edu", "45.88.67.3", 0)],
           auth="spf=pass smtp.mailfrom=uni-examp1e.edu; dkim=pass header.d=uni-examp1e.edu; "
                "dmarc=none header.from=uni-examp1e.edu"))
case("S20_hostile_encoded", "suspicious", "malformed",
     "Hostile header content (encoded control characters, very long subject) on a spoof.",
     build(sender="billing@apple.com", from_display="Apple",
           subject="=?utf-8?b?" + "WW91ciBpQ2xvdWQgc3RvcmFnZSBpcyBmdWxsAAAAAA==" + "?= " + "A" * 3000,
           sending_hops=[hop("x1.mass-mailer.top", "193.233.48.9", 0)],
           return_path="b@mass-mailer.top",
           auth="spf=fail smtp.mailfrom=mass-mailer.top; dkim=none; "
                "dmarc=fail (p=REJECT) header.from=apple.com"))


def split_for(index_in_category: int) -> str:
    # Alternate within each category so both splits cover every category.
    return "tune" if index_in_category % 2 == 0 else "test"


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    counters = {}
    rows = []
    for name, label, category, description, raw in CASES:
        key = (label, category)
        counters[key] = counters.get(key, 0) + 1
        filename = f"{name}.eml"
        (OUT_DIR / filename).write_bytes(raw)
        rows.append({"filename": filename, "label": label, "category": category,
                     "split": split_for(counters[key] - 1), "description": description})
    with open(HERE / "test_cases.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} cases to {OUT_DIR}")


if __name__ == "__main__":
    main()
