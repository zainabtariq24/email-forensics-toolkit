from conftest import BASIC, NOW, make_email, replace_header
from module1_header_extraction import parse_email
from module2_route_reconstruction import analyze_route, parse_received


def kinds(route):
    return {a.kind for a in route.anomalies}


def test_parse_received_typical_gmail_style():
    hop = parse_received(
        "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])\r\n"
        "  by mx.google.com with SMTPS id k2sor1 for <x@y.com>\r\n"
        "  (Google Transport Security); Tue, 3 Oct 2023 10:00:00 -0700 (PDT)")
    assert hop.from_helo == "mail-sor-f41.google.com"
    assert hop.from_rdns == "mail-sor-f41.google.com"
    assert hop.from_ip == "209.85.220.41" and hop.from_ip_scope == "public"
    assert hop.by_host == "mx.google.com"
    assert hop.protocol == "smtps"
    assert hop.for_address == "x@y.com"
    assert hop.timestamp.isoformat() == "2023-10-03T10:00:00-07:00"


def test_keywords_inside_comments_are_ignored():
    hop = parse_received("by mail.example.com (Postfix, from userid 1000) id 4F; "
                         "Mon, 14 Sep 2026 09:00:00 +0000")
    assert hop.by_host == "mail.example.com"
    assert hop.from_helo is None


def test_ipv6_literal():
    hop = parse_received("from host ([IPv6:2001:db8::1]) by mx.example.com; "
                         "Mon, 14 Sep 2026 09:00:00 +0000")
    assert hop.from_ip == "2001:db8::1"


def test_malformed_received_records_problems():
    hop = parse_received("garbage without structure")
    assert hop.timestamp is None
    assert any("timestamp" in p for p in hop.problems)
    assert any("'by'" in p for p in hop.problems)


def test_route_is_reversed_into_delivery_order_and_trust(basic_raw):
    route = analyze_route(parse_email(basic_raw), now=NOW)
    assert [h.by_host for h in route.hops] == ["mx1.uni-example.edu",
                                               "mailbox.uni-example.edu"]
    assert route.trusted_domains == ["uni-example.edu"]
    assert all(h.trusted for h in route.hops)
    assert route.origin_ip == "81.2.69.160"
    assert route.hops[1].delay_seconds == 10
    assert route.total_transit_seconds == 10
    assert not kinds(route) - {"long-delay"}


def test_forged_lower_hops_are_untrusted_and_time_reversal_detected():
    forged = ("Received: from fake.paypal.com (fake [8.8.8.8]) by relay.paypal.com; "
              "Mon, 14 Sep 2026 12:00:00 +0000")
    route = analyze_route(parse_email(make_email(*BASIC, forged)), now=NOW)
    assert route.hops[0].by_host == "relay.paypal.com"
    assert route.hops[0].trusted is False
    assert route.origin_ip == "81.2.69.160"  # from the first trusted hop, not the forgery
    assert route.claimed_origin_ip == "8.8.8.8"
    assert "time-reversal" in kinds(route)


def test_clock_skew_within_tolerance_is_not_flagged():
    lines = replace_header(BASIC, "Received: from mx1",
                           "Received: from mx1.uni-example.edu ([10.0.0.5]) by "
                           "mailbox.uni-example.edu; Mon, 14 Sep 2026 09:27:00 +0000")
    route = analyze_route(parse_email(make_email(*lines)), now=NOW)
    assert "time-reversal" not in kinds(route)


def test_date_after_delivery_and_future_date():
    lines = replace_header(BASIC, "Date", "Date: Mon, 14 Sep 2026 15:00:00 +0000")
    assert "date-after-delivery" in kinds(analyze_route(parse_email(make_email(*lines)), now=NOW))
    lines = replace_header(BASIC, "Date", "Date: Mon, 14 Sep 2099 15:00:00 +0000")
    assert "future-date" in kinds(analyze_route(parse_email(make_email(*lines)), now=NOW))


def test_missing_route():
    route = analyze_route(parse_email(make_email("From: a@b.com", "Subject: x")), now=NOW)
    assert route.hops == [] and "missing-route" in kinds(route)


def test_explicit_trusted_domains_override_inference(basic_raw):
    route = analyze_route(parse_email(basic_raw), trusted_domains=["other.org"], now=NOW)
    assert route.trusted_domains == ["other.org"]
    assert not any(h.trusted for h in route.hops)
    assert "no-trusted-hop" in kinds(route)
