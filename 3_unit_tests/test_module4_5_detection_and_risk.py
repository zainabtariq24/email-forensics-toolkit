"""Module 4 (look-alike domains, spoofing rules) and Module 5 (risk scoring)."""

import json

import pytest

from conftest import BASIC, NOW, make_email, replace_header
from analyzer import AnalysisSettings, analyze_email
from module4_spoofing_detection import (Finding, check_lookalike,
                                                        compare_related_domains,
                                                        levenshtein, organizational_domain)
from module5_risk_assessment import APPROACHES, assess_risk


def analyse(lines, **settings):
    return analyze_email(make_email(*lines), AnalysisSettings(**settings),
                         analysis_time=NOW)


def rules(result):
    return {f["rule_id"]: f["severity"] for f in result["findings"]}


def with_auth(lines, value):
    return replace_header(lines, "Authentication-Results",
                          f"Authentication-Results: mx1.uni-example.edu; {value}")


def test_clean_message_has_no_scored_findings(basic_raw):
    result = analyze_email(basic_raw, analysis_time=NOW)
    assert result["findings"] == []
    assert result["risk"]["category"] == "low"
    json.dumps(result, default=str)  # serialisable


def test_reply_to_mismatch_with_freemail():
    r = rules(analyse(BASIC + ["Reply-To: <alice.payments@gmail.com>"]))
    assert r["SENDER-REPLYTO-MISMATCH"] == "medium"


def test_reply_to_same_organisation_not_flagged():
    r = rules(analyse(BASIC + ["Reply-To: <support@help.sender.com>"]))
    assert "SENDER-REPLYTO-MISMATCH" not in r


def test_return_path_mismatch_is_low():
    r = rules(analyse(replace_header(BASIC, "Return-Path", "Return-Path: <b@esp.net>")))
    assert r["SENDER-RETURNPATH-MISMATCH"] == "low"


def test_dmarc_and_spf_failure():
    r = rules(analyse(with_auth(BASIC, "spf=fail smtp.mailfrom=sender.com; dkim=none; "
                                       "dmarc=fail (p=REJECT) header.from=sender.com")))
    assert r["AUTH-DMARC-FAIL"] == "high"
    assert r["AUTH-SPF-FAIL"] == "medium"


def test_forwarded_mail_downgrades_spf_failure():
    lines = with_auth(BASIC, "spf=fail smtp.mailfrom=sender.com; dkim=pass header.d=sender.com; "
                             "dmarc=pass header.from=sender.com") + ["X-Forwarded-To: bob@x.org"]
    r = rules(analyse(lines))
    assert r["AUTH-SPF-FAIL"] == "low"
    assert "CONTEXT-FORWARDED" in r


def test_mailing_list_with_arc_downgrades_dmarc_and_dkim():
    lines = with_auth(BASIC, "spf=pass smtp.mailfrom=list.org; dkim=fail header.d=sender.com; "
                             "dmarc=fail header.from=sender.com; arc=pass") + [
        "List-Id: <dev.list.org>", "ARC-Seal: i=1; cv=none; d=list.org"]
    r = rules(analyse(lines))
    assert r["AUTH-DMARC-FAIL"] == "medium"
    assert r["AUTH-DKIM-FAIL"] == "low"
    assert "CONTEXT-MAILING-LIST" in r


def test_not_aligned_when_no_dmarc_recorded():
    r = rules(analyse(with_auth(BASIC, "spf=pass smtp.mailfrom=esp.net; dkim=pass header.d=esp.net")))
    assert r["AUTH-NOT-ALIGNED"] == "medium"


def test_missing_auth():
    r = rules(analyse(replace_header(BASIC, "Authentication-Results", None)))
    assert r["AUTH-MISSING"] == "low"


def test_forged_authentication_results_detected():
    lines = with_auth(BASIC, "spf=fail smtp.mailfrom=x.net; dmarc=fail header.from=sender.com") + [
        "Authentication-Results: mx.google.com; spf=pass; dmarc=pass header.from=sender.com"]
    assert "AUTH-UNTRUSTED-CLAIMS" in rules(analyse(lines))


def test_display_name_with_other_address():
    lines = replace_header(BASIC, "From", 'From: "support@apple.com" <alice@sender.com>')
    assert rules(analyse(lines))["SENDER-DISPLAYNAME-ADDRESS"] == "high"


def test_display_name_brand_on_freemail():
    lines = replace_header(BASIC, "From", 'From: "PayPal Support" <pp.help@gmail.com>')
    assert rules(analyse(lines))["SENDER-DISPLAYNAME-BRAND"] == "high"


def test_genuine_brand_display_name_not_flagged():
    lines = replace_header(BASIC, "From", 'From: "PayPal" <service@paypal.com>')
    assert "SENDER-DISPLAYNAME-BRAND" not in rules(analyse(lines))


def test_lookalike_from_domain():
    lines = replace_header(BASIC, "From", 'From: "PayPal" <service@paypa1.com>')
    assert rules(analyse(lines))["DOMAIN-LOOKALIKE"] == "high"


def test_lookalike_of_configured_organisation():
    lines = replace_header(BASIC, "From", "From: <it@uni-examp1e.edu>")
    assert "DOMAIN-LOOKALIKE" in rules(analyse(lines, protected_domains=["uni-example.edu"]))


def test_internal_lookalike_reply_to():
    r = rules(analyse(BASIC + ["Reply-To: <alice@sendor.com>"]))
    assert r["DOMAIN-INTERNAL-LOOKALIKE"] == "high"


def test_duplicate_from_header():
    r = rules(analyse(BASIC + ["From: <ceo@bank.com>"]))
    assert r["HEADER-DUPLICATE"] == "high"


def test_route_inconsistency():
    lines = BASIC + ["Received: from a (a [8.8.8.8]) by fake.relay.net; Mon, 14 Sep 2026 13:00:00 +0000"]
    assert "ROUTE-INCONSISTENT" in rules(analyse(lines))


def test_missing_route_only_for_full_messages():
    no_route = [l for l in BASIC if not l.startswith("Received")]
    assert "ROUTE-MISSING" in rules(analyse(no_route))
    headers_only = analyze_email("\r\n".join(no_route).encode(), analysis_time=NOW)
    assert "ROUTE-MISSING" not in rules(headers_only)


def test_every_finding_is_explained():
    lines = replace_header(BASIC, "From", 'From: "PayPal" <x@paypa1.com>') + [
        "Reply-To: <x@gmail.com>", "From: <dup@x.com>"]
    for f in analyse(lines)["findings"]:
        assert f["evidence"] and f["why_it_matters"] and f["limitations"]


# ------------------------------------------------------------------ scoring
def finding(rule, severity, category="sender"):
    return Finding(rule, rule, severity, category, ["e"], "w", "l")


def test_severity_sum_scoring():
    risk = assess_risk([finding("SENDER-REPLYTO-MISMATCH", "medium"),
                        finding("SENDER-RETURNPATH-MISMATCH", "low")], "severity_sum")
    assert risk.score == 4 and risk.category == "medium" and risk.flagged
    assert [c.rule_id for c in risk.contributions] == ["SENDER-REPLYTO-MISMATCH",
                                                       "SENDER-RETURNPATH-MISMATCH"]


def test_rule_weighted_scoring():
    risk = assess_risk([finding("DOMAIN-LOOKALIKE", "high")], "rule_weighted")
    assert risk.score == 5 and risk.category == "high"


def test_max_severity_escalation():
    one = assess_risk([finding("A", "medium", "sender")], "max_severity")
    two = assess_risk([finding("A", "medium", "sender"),
                       finding("B", "medium", "authentication")], "max_severity")
    assert one.category == "medium" and two.category == "high"


@pytest.mark.parametrize("approach", APPROACHES)
def test_no_findings_is_low_for_every_approach(approach):
    risk = assess_risk([], approach)
    assert risk.category == "low" and not risk.flagged and "not a calibrated" in risk.disclaimer


def test_info_findings_do_not_score():
    risk = assess_risk([finding("CONTEXT-MAILING-LIST", "info", "context")], "severity_sum")
    assert risk.score == 0 and risk.contributions == []


def test_unknown_approach_rejected():
    with pytest.raises(ValueError):
        assess_risk([], "magic")


def test_result_records_hash_settings_and_limitations(basic_raw):
    result = analyze_email(basic_raw, AnalysisSettings(scoring_approach="max_severity"),
                           analysis_time=NOW)
    assert len(result["evidence"]["sha256"]) == 64
    assert result["metadata"]["settings"]["scoring_approach"] == "max_severity"
    assert result["risk"]["approach"] == "max_severity"
    assert result["limitations"] and result["next_steps"]


def test_receivers_own_arc_seal_is_not_forwarding():
    own = BASIC + ["ARC-Seal: i=1; a=rsa-sha256; cv=none; d=uni-example.edu; s=arc; b=x"]
    assert "CONTEXT-FORWARDED" not in rules(analyse(own))
    foreign = BASIC + ["ARC-Seal: i=1; a=rsa-sha256; cv=none; d=forwarder.org; s=arc; b=x"]
    assert "CONTEXT-FORWARDED" in rules(analyse(foreign))


# ------------------------------------------------------------------ look-alike domains
@pytest.mark.parametrize("domain,expected", [
    ("mail.paypal.com", "paypal.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("uni.edu.pk", "uni.edu.pk"),
    ("localhost", "localhost"),
    (None, None),
])
def test_organizational_domain(domain, expected):
    assert organizational_domain(domain) == expected


def techniques(domain, protected=None):
    kwargs = {"protected": protected} if protected else {}
    return {(m.resembles, m.technique) for m in check_lookalike(domain, **kwargs)}


@pytest.mark.parametrize("domain,target,technique", [
    ("paypa1.com", "paypal.com", "character-substitution"),
    ("rnicrosoft.com", "microsoft.com", "character-substitution"),
    ("linkedln.com", "linkedin.com", "character-substitution"),
    ("xn--pypal-4ve.com", "paypal.com", "idn-homograph"),
    ("dropboxx.com", "dropbox.com", "typosquat"),
    ("paypal-secure-login.com", "paypal.com", "brand-embedded"),
    ("microsoft.com.evil-portal.net", "microsoft.com", "brand-in-subdomain"),
    ("paypal.co.uk", "paypal.com", "suffix-swap"),
])
def test_lookalikes_detected(domain, target, technique):
    assert (target, technique) in techniques(domain)


@pytest.mark.parametrize("domain", [
    "paypal.com", "mail.paypal.com", "amazonses.com", "gmail.com", "purchase.com",
    "groups.io", "pineapple-farm.com", "uni-example.edu", "example.org",
])
def test_legitimate_or_unrelated_domains_not_flagged(domain):
    assert techniques(domain) == set()


def test_custom_protected_domain():
    assert ("uni-example.edu", "character-substitution") in techniques(
        "uni-examp1e.edu", ["uni-example.edu"])


def test_compare_related_domains():
    assert compare_related_domains("acme-supplies.com", "acme-suppiies.com") is not None
    assert compare_related_domains("acme-supplies.com", "mail.acme-supplies.com") is None
    assert compare_related_domains("acme-supplies.com", "gmail.com") is None


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    assert levenshtein("same", "same") == 0
