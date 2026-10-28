from conftest import BASIC, NOW, make_email, replace_header
from module1_header_extraction import parse_email
from module2_route_reconstruction import analyze_route
from module3_authentication import (analyze_authentication,
                                                    parse_authentication_results,
                                                    parse_received_spf)


def run(lines, **kwargs):
    parsed = parse_email(make_email(*lines))
    route = analyze_route(parsed, now=NOW)
    return analyze_authentication(parsed, route, **kwargs)


def with_auth(value):
    return replace_header(BASIC, "Authentication-Results",
                          f"Authentication-Results: mx1.uni-example.edu; {value}")


def test_parse_rfc8601_header():
    authserv, results = parse_authentication_results(
        "mx.google.com; dkim=pass header.i=@x.com header.s=s1 header.b=abc; "
        "spf=softfail (google.com: domain of b@y.com does not designate 1.2.3.4) "
        "smtp.mailfrom=b@y.com; dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=x.com")
    assert authserv == "mx.google.com"
    by_method = {r.method: r for r in results}
    assert by_method["spf"].result == "softfail"
    assert by_method["spf"].properties["smtp.mailfrom"] == "b@y.com"
    assert by_method["dkim"].properties["header.s"] == "s1"
    assert by_method["dmarc"].properties["p"] == "REJECT"


def test_microsoft_style_header_without_authserv_id():
    authserv, results = parse_authentication_results(
        "spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x.com; dkim=pass "
        "(signature was verified) header.d=x.com;dmarc=pass action=none header.from=x.com;"
        "compauth=pass reason=100")
    assert authserv is None
    assert [r.method for r in results] == ["spf", "dkim", "dmarc", "compauth"]


def test_received_spf():
    r = parse_received_spf("Fail (domain of x@y.com does not designate 1.2.3.4) "
                           "client-ip=1.2.3.4; envelope-from=<x@y.com>;")
    assert r.result == "fail" and r.properties["smtp.mailfrom"] == "x@y.com"


def test_all_pass_aligned(basic_raw):
    a = run(BASIC)
    assert (a.spf.status, a.dkim.status, a.dmarc.status) == ("pass", "pass", "pass")
    assert a.trusted_authserv_ids == ["mx1.uni-example.edu"]
    assert a.alignment["spf_aligned"] and a.alignment["dkim_aligned"]


def test_status_normalisation():
    a = run(with_auth("spf=softfail smtp.mailfrom=sender.com; dkim=temperror header.d=sender.com; "
                      "dmarc=none header.from=sender.com"))
    assert a.spf.status == "fail" and a.spf.raw_result == "softfail"
    assert a.dkim.status == "inconclusive"
    assert a.dmarc.status == "neutral"


def test_missing_results():
    a = run(replace_header(BASIC, "Authentication-Results", None))
    assert (a.spf.status, a.dkim.status, a.dmarc.status) == ("missing", "missing", "missing")
    assert not a.any_trusted


def test_untrusted_headers_are_ignored():
    forged = ("Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bank.com; "
              "dmarc=pass header.from=bank.com")
    lines = with_auth("spf=fail smtp.mailfrom=evil.com; dmarc=fail header.from=sender.com")
    a = run(lines + [forged])
    assert a.spf.status == "fail" and a.dmarc.status == "fail"
    assert {r.authserv_id for r in a.untrusted_results} == {"mx.google.com"}


def test_topmost_authserv_from_other_domain_is_not_auto_trusted():
    lines = replace_header(BASIC, "Authentication-Results",
                           "Authentication-Results: mx.attacker.net; spf=pass; dmarc=pass")
    a = run(lines)
    assert not a.any_trusted
    assert a.dmarc.status == "missing"


def test_explicit_trusted_authserv_id():
    lines = replace_header(BASIC, "Authentication-Results",
                           "Authentication-Results: mx.attacker.net; dmarc=fail")
    a = run(lines, trusted_authserv_ids=["mx.attacker.net"])
    assert a.dmarc.status == "fail"


def test_dkim_best_signature_wins():
    a = run(with_auth("dkim=fail header.d=other.net; dkim=pass header.d=sender.com"))
    assert a.dkim.status == "pass" and a.dkim.domain == "sender.com"


def test_unaligned_passes():
    a = run(with_auth("spf=pass smtp.mailfrom=esp.net; dkim=pass header.d=esp.net"))
    assert a.alignment["computed_dmarc_alignment"] == "fail"
    assert a.dkim_passing_domains == ["esp.net"]


def test_subdomain_alignment_is_relaxed():
    a = run(with_auth("spf=pass smtp.mailfrom=bounce.sender.com"))
    assert a.alignment["spf_aligned"]


def test_arc_original_results_recorded():
    lines = with_auth("spf=fail smtp.mailfrom=sender.com; arc=pass") + [
        "ARC-Authentication-Results: i=1; fwd.example; spf=pass smtp.mailfrom=sender.com; dkim=pass"]
    a = run(lines)
    assert a.arc.status == "pass"
    assert a.arc.details["original_spf"] == "pass"


def test_gmail_style_dkim_header_i_counts_for_alignment():
    a = run(with_auth("dkim=pass header.i=@sender.com header.s=k1; "
                      "spf=pass smtp.mailfrom=bounce@esp.net"))
    assert a.dkim_passing_domains == ["sender.com"]
    assert a.alignment["dkim_aligned"]
