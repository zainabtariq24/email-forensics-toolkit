"""Module 6 (evidence integrity, PDF report), the Flask app and a dataset regression check."""

import csv
import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import NOW, ROOT
from analyzer import analyze_email
from module6_forensic_report import (EvidenceError, EvidenceStore,
                                                     build_report, new_case_id,
                                                     safe_filename, sha256_hex,
                                                     validate_case_id)


# ------------------------------------------------------------------ integrity
def test_sha256_known_value():
    assert sha256_hex(b"abc") == ("ba7816bf8f01cfea414140de5dae2223"
                                  "b00361a396177a9cb410ff61f20015ad")


def test_case_id_format_and_validation():
    cid = new_case_id(NOW)
    assert validate_case_id(cid) == cid and cid.startswith("EFT-20261001-")
    for bad in ["../etc", "EFT-2026-XYZ", "EFT-20261001-abcdef12", ""]:
        with pytest.raises(EvidenceError):
            validate_case_id(bad)


def test_safe_filename():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("my mail (1).eml") == "my_mail_1_.eml"
    assert safe_filename(None) == "pasted-headers.txt"


def test_store_preserves_original_and_detects_tampering(tmp_path, basic_raw):
    store = EvidenceStore(tmp_path)
    cid = new_case_id()
    manifest = store.store_original(cid, basic_raw, "msg.eml", NOW, "file upload")
    assert manifest["sha256"] == sha256_hex(basic_raw)
    original = tmp_path / cid / "evidence" / "original.eml"
    assert original.read_bytes() == basic_raw
    assert not os.access(original, os.W_OK)  # read-only
    assert store.verify(cid)["intact"]

    os.chmod(original, 0o600)
    original.write_bytes(basic_raw + b"tampered")
    check = store.verify(cid)
    assert not check["intact"] and check["current_sha256"] != check["expected_sha256"]


def test_derived_results_stored_separately(tmp_path, basic_raw):
    store = EvidenceStore(tmp_path)
    cid = new_case_id()
    store.store_original(cid, basic_raw, "m.eml", NOW, "file upload")
    store.save_derived(cid, "analysis.json", {"x": 1})
    assert (tmp_path / cid / "derived" / "analysis.json").exists()
    assert store.load_derived(cid) == {"x": 1}
    with pytest.raises(EvidenceError):
        store.save_derived(cid, "../escape.json", {})


# ------------------------------------------------------------------ report
def test_pdf_report_generated_and_escapes_markup(basic_raw):
    raw = basic_raw.replace(b"Subject: Hello", b"Subject: <b>&<font> injected")
    analysis = json.loads(json.dumps(analyze_email(raw, analysis_time=NOW), default=str))
    pdf = build_report(analysis, {"intact": True, "current_sha256": "x",
                                  "verified_at_utc": "now"}, {"original_filename": "m.eml"})
    assert pdf.startswith(b"%PDF") and len(pdf) > 3000


# ------------------------------------------------------------------ Flask app
@pytest.fixture
def client(tmp_path):
    from app import create_app
    app = create_app(tmp_path)
    app.config["TESTING"] = True
    return app.test_client()


def test_upload_flow_and_downloads(client, basic_raw):
    resp = client.post("/analyze", data={
        "eml_file": (io.BytesIO(basic_raw), "message.eml"),
        "scoring_approach": "rule_weighted"}, content_type="multipart/form-data")
    assert resp.status_code == 302
    case_url = resp.headers["Location"]
    case_id = re.search(r"EFT-\d{8}-[0-9A-F]{8}", case_url).group(0)

    page = client.get(case_url)
    assert page.status_code == 200 and sha256_hex(basic_raw).encode() in page.data
    assert b"intact" in page.data

    pdf = client.get(f"/case/{case_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")

    exported = client.get(f"/case/{case_id}/analysis.json").get_json()
    assert exported["risk"]["approach"] == "rule_weighted"
    assert exported["integrity_check"]["intact"]


def test_pasted_headers_and_html_is_escaped(client):
    resp = client.post("/analyze", data={
        "raw_headers": "From: <script>alert(1)</script> <a@b.com>\nSubject: <img src=x>\n"},
        follow_redirects=True)
    assert resp.status_code == 200
    assert b"<script>alert(1)" not in resp.data and b"&lt;img src=x&gt;" in resp.data


def test_empty_and_unusable_input(client):
    assert b"Upload a .eml" in client.post("/analyze", data={}, follow_redirects=True).data
    resp = client.post("/analyze", data={"raw_headers": "just some words"},
                       follow_redirects=True)
    assert b"Could not analyse input" in resp.data


def test_unknown_or_malicious_case_ids_404(client):
    assert client.get("/case/EFT-20260101-DEADBEEF").status_code == 404
    assert client.get("/case/..%2F..%2Fetc").status_code == 404


# ------------------------------------------------------------------ dataset
def load_dataset():
    with open(ROOT / "4_labelled_test_emails" / "test_cases.csv", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.mark.parametrize("case", load_dataset(), ids=lambda c: c["filename"])
def test_every_dataset_case_analyses_without_error(case):
    raw = (ROOT / "4_labelled_test_emails" / "emails" / case["filename"]).read_bytes()
    result = analyze_email(raw, analysis_time=datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert result["risk"]["category"] in ("low", "medium", "high")
