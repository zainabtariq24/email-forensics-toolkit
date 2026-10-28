"""Flask web interface for the Email Forensics Toolkit.

    python 2_web_interface/app.py            # http://127.0.0.1:5050

Every submission becomes a case: the original bytes are stored read-only with
their SHA-256, the derived analysis is stored separately, and reports are
generated from the stored analysis after re-verifying the evidence hash.
"""

from __future__ import annotations

import json
import mimetypes
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, url_for)

GUI_DIR = Path(__file__).resolve().parent
BASE_DIR = GUI_DIR.parent
sys.path.insert(0, str(BASE_DIR / "1_forensic_analysis_modules"))  # the analysis modules

from analyzer import (DEFAULT_SCORING_APPROACH, AnalysisSettings,
                                      analyze_email)
from module1_header_extraction import MAX_INPUT_BYTES, InputError
from module5_risk_assessment import APPROACHES
from module6_forensic_report import (TOOL_NAME, EvidenceError, EvidenceStore,
                                                     build_report, new_case_id,
                                                     __version__, validate_case_id)

SAMPLE_DIR = BASE_DIR / "4_labelled_test_emails" / "emails"

# Windows can map these extensions to the wrong type via the registry; with the
# nosniff header the browser would then refuse the file.  Pin them everywhere.
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("font/woff2", ".woff2")


def list_samples():
    """Dataset emails offered as one-click demo inputs."""
    if not SAMPLE_DIR.is_dir():
        return []
    return sorted(p.name for p in SAMPLE_DIR.glob("*.eml"))


def _split_list(value: str):
    return [v.strip().lower() for v in (value or "").replace(",", " ").split() if v.strip()]


def create_app(case_dir=None) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("EFT_SECRET_KEY", secrets.token_hex(16))
    app.config["MAX_CONTENT_LENGTH"] = MAX_INPUT_BYTES + 64 * 1024
    store = EvidenceStore(case_dir or os.environ.get("EFT_CASE_DIR", BASE_DIR / "cases"))
    app.config["STORE"] = store

    @app.context_processor
    def globals_():
        return {"tool_name": TOOL_NAME, "tool_version": __version__}

    def render_index(**extra):
        return render_template("index.html", approaches=APPROACHES,
                               default_approach=DEFAULT_SCORING_APPROACH,
                               samples=list_samples(), **extra)

    @app.get("/")
    def index():
        return render_index()

    @app.post("/analyze")
    def analyze():
        upload = request.files.get("eml_file")
        pasted = request.form.get("raw_headers", "")
        sample = request.form.get("sample", "")
        if upload and upload.filename:
            raw = upload.read()
            source, method = upload.filename, "file upload"
        elif pasted.strip():
            raw = pasted.encode("utf-8")
            source, method = "pasted-headers.txt", "pasted text"
        elif sample in list_samples():  # whitelist: never build paths from input
            raw = (SAMPLE_DIR / sample).read_bytes()
            source, method = sample, "sample dataset"
        else:
            flash("Upload a .eml file or paste raw headers.")
            return redirect(url_for("index"))

        approach = request.form.get("scoring_approach", DEFAULT_SCORING_APPROACH)
        settings = AnalysisSettings(
            trusted_domains=_split_list(request.form.get("trusted_domains", "")),
            trusted_authserv_ids=_split_list(request.form.get("trusted_authserv_ids", "")),
            protected_domains=_split_list(request.form.get("protected_domains", "")),
            dns_lookups=request.form.get("dns_lookups") == "on",
            scoring_approach=approach if approach in APPROACHES else DEFAULT_SCORING_APPROACH,
        )
        now = datetime.now(timezone.utc)
        case_id = new_case_id(now)
        try:
            result = analyze_email(raw, settings, source_name=source, case_id=case_id,
                                   analysis_time=now)
        except InputError as exc:
            flash(f"Could not analyse input: {exc}")
            return redirect(url_for("index"))

        # Evidence is stored only once analysis succeeded, then the derived
        # results are written separately from it.
        store.store_original(case_id, raw, source, now, method)
        store.save_derived(case_id, "analysis.json", result)
        return redirect(url_for("case", case_id=case_id))

    def _load(case_id):
        try:
            validate_case_id(case_id)
            return (store.load_derived(case_id), store.verify(case_id),
                    store.load_manifest(case_id))
        except EvidenceError:
            abort(404)

    @app.get("/case/<case_id>")
    def case(case_id):
        analysis, integrity, manifest = _load(case_id)
        return render_template("result.html", a=analysis, integrity=integrity,
                               manifest=manifest)

    @app.get("/case/<case_id>/report.pdf")
    def report(case_id):
        analysis, integrity, manifest = _load(case_id)
        pdf = build_report(analysis, integrity, manifest)
        store.save_derived(case_id, "report.pdf", pdf)
        return Response(pdf, mimetype="application/pdf", headers={
            "Content-Disposition": f'attachment; filename="{case_id}-report.pdf"'})

    @app.get("/case/<case_id>/analysis.json")
    def export_json(case_id):
        analysis, integrity, _ = _load(case_id)
        payload = {**analysis, "integrity_check": integrity}
        return Response(json.dumps(payload, indent=2, default=str),
                        mimetype="application/json", headers={
                            "Content-Disposition": f'attachment; filename="{case_id}.json"'})

    @app.errorhandler(413)
    def too_large(_):
        flash(f"Input too large; the limit is {MAX_INPUT_BYTES // (1024 * 1024)} MiB.")
        return redirect(url_for("index"))

    @app.errorhandler(404)
    def not_found(_):
        return render_index(error="Case not found."), 404

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:")
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    return app


if __name__ == "__main__":
    # Bound to localhost: evidence handling tools should not be exposed publicly.
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5050)), debug=False)
