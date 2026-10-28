import pytest

from conftest import BASIC, make_email, replace_header
from module1_header_extraction import (MAX_INPUT_BYTES, InputError,
                                                       classify_ip, extract_ips,
                                                       parse_email)


def kinds(parsed, field):
    return {i.kind for i in parsed.issues if i.field == field}


def test_extracts_core_fields(basic_raw):
    p = parse_email(basic_raw)
    assert p.from_addrs[0].address == "alice@sender.com"
    assert p.from_addrs[0].display_name == "Alice Sender"
    assert p.from_domain == "sender.com"
    assert p.to_addrs[0].domain == "uni-example.edu"
    assert p.return_path.domain == "sender.com"
    assert p.subject == "Hello"
    assert p.message_id_domain == "sender.com"
    assert p.date.isoformat() == "2026-09-14T09:29:30+00:00"
    assert len(p.received) == 2
    assert p.received[0].startswith("from mx1.uni-example.edu")  # original order kept
    assert len(p.authentication_results) == 1
    assert not p.headers_only


def test_ips_are_validated_and_classified(basic_raw):
    p = parse_email(basic_raw)
    scopes = {i.ip: i.scope for i in p.ips}
    assert scopes == {"10.0.0.5": "private", "81.2.69.160": "public"}
    assert extract_ips("from x [999.1.1.1] (1.2.3)") == []
    assert classify_ip("2001:4860:4860::8888") == "public"
    assert classify_ip("::1") == "loopback"


def test_folded_headers_are_unfolded():
    p = parse_email(make_email("From: a@b.com", "Subject: part one\r\n  part two",
                               "Date: Mon, 14 Sep 2026 09:29:30 +0000"))
    assert p.subject == "part one part two"


def test_encoded_word_subject_and_display_name():
    p = parse_email(make_email("From: =?utf-8?b?w4FsaWNl?= <a@b.com>",
                               "Subject: =?utf-8?q?Caf=C3=A9?=",
                               "Date: Mon, 14 Sep 2026 09:29:30 +0000"))
    assert p.subject == "Café"
    assert p.from_addrs[0].display_name == "Álice"


def test_missing_required_and_expected_fields():
    p = parse_email(make_email("Subject: only a subject"))
    assert "missing" in kinds(p, "From")
    assert "missing" in kinds(p, "Date")
    assert "missing" in kinds(p, "Message-ID")


def test_duplicate_singleton_fields_flagged():
    p = parse_email(make_email(*BASIC, "From: <other@evil.com>", "Subject: Second"))
    dup = {i.field: i.severity for i in p.issues if i.kind == "duplicate"}
    assert dup["From"] == "high"
    assert dup["Subject"] == "medium"
    # Received is allowed to repeat
    assert "Received" not in dup


def test_malformed_fields():
    lines = replace_header(BASIC, "Message-ID", "Message-ID: not-a-valid-id")
    lines = replace_header(lines, "Date", "Date: yesterday at noon")
    lines = replace_header(lines, "From", "From: Totally Not An Address")
    p = parse_email(make_email(*lines))
    assert "malformed" in kinds(p, "Message-ID")
    assert "malformed" in kinds(p, "Date")
    assert "malformed" in kinds(p, "From")
    assert p.date is None


def test_null_return_path():
    p = parse_email(make_email(*replace_header(BASIC, "Return-Path", "Return-Path: <>")))
    assert p.return_path_null and p.return_path is None


def test_headers_only_input_with_leading_blank_lines():
    raw = ("\n\n" + "\n".join(BASIC)).encode()
    p = parse_email(raw)
    assert p.headers_only
    assert p.from_domain == "sender.com"


@pytest.mark.parametrize("raw", [b"", b"\n\n\n", b"this is not an email at all"])
def test_unusable_input_raises_input_error(raw):
    with pytest.raises(InputError):
        parse_email(raw)


def test_oversized_input_rejected():
    with pytest.raises(InputError):
        parse_email(b"From: a@b.com\r\n" + b"x" * (MAX_INPUT_BYTES + 1))


def test_non_bytes_rejected():
    with pytest.raises(InputError):
        parse_email("From: a@b.com")


def test_hostile_bytes_do_not_crash():
    raw = (b"From: \xff\xfe evil <a@b.com>\r\nSubject: \x00\x01\x02 null\r\n"
           b"Date: Mon, 14 Sep 2026 09:29:30 +0000\r\n\r\n\xff\x00body")
    p = parse_email(raw)
    assert p.decoding_replacements
    assert "\x00" not in p.subject
    assert any(i.kind == "suspicious-encoding" for i in p.issues)


def test_extremely_long_header_is_truncated_for_display():
    p = parse_email(make_email("From: a@b.com", "Subject: " + "A" * 50000,
                               "Date: Mon, 14 Sep 2026 09:29:30 +0000"))
    assert len(p.subject) < 1100 and "truncated" in p.subject


def test_many_headers_capped():
    lines = ["From: a@b.com"] + [f"X-Junk-{i}: v" for i in range(2500)]
    p = parse_email(make_email(*lines))
    assert len(p.headers) == 2000
    assert any("only the first" in i.detail for i in p.issues)


def test_malformed_encoded_word_falls_back():
    p = parse_email(make_email("From: a@b.com", "Subject: =?bogus?x?abc?=",
                               "Date: Mon, 14 Sep 2026 09:29:30 +0000"))
    assert p.subject  # no exception, some value kept


def test_gmail_sender_details_summary_is_rejected_with_guidance():
    pasted = ("From:\tSemrush <p@semrush.com>\r\nto:\t\r\nMe <me@gmail.com>\r\n"
              "mailed-by:\tmailer-ses.semrush.com\r\nsigned-by:\tsemrush.com\r\n").encode()
    with pytest.raises(InputError, match="Show original"):
        parse_email(pasted)


def test_ip_listed_once_even_if_in_several_headers():
    p = parse_email(make_email(*BASIC, "Received-SPF: pass client-ip=81.2.69.160;"))
    assert [i.ip for i in p.ips].count("81.2.69.160") == 1
