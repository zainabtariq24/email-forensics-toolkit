"""Module 6 - Forensic report generation and evidence integrity.

Part A preserves the evidence: case identifiers, SHA-256 hashing and a case
store that keeps the original bytes read-only and separate from derived results.

Layout of one case directory::

    <store>/<case_id>/
        evidence/original.eml      exact bytes received, made read-only
        evidence/manifest.json     SHA-256, size, original filename, timestamp
        derived/analysis.json      normalised/derived results (never mixed with evidence)
        derived/report.pdf         generated report

The original bytes are hashed on intake and re-verified before any report is
generated, so the report can state whether the evidence is unchanged.

Part B builds the downloadable PDF report (ReportLab) from the stored analysis
JSON plus an integrity re-check of the stored original.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import stat
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

TOOL_NAME = "Email Forensics Toolkit"
__version__ = "1.0.0"

# ============================================================================
# Part A - evidence integrity
# ============================================================================

CASE_ID_RE = re.compile(r"^EFT-\d{8}-[0-9A-F]{8}$")


class EvidenceError(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_case_id(now: Optional[datetime] = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"EFT-{now:%Y%m%d}-{secrets.token_hex(4).upper()}"


def validate_case_id(case_id: str) -> str:
    """Case IDs become directory names, so reject anything unexpected."""
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise EvidenceError(f"Invalid case identifier: {case_id!r}")
    return case_id


def safe_filename(name: Optional[str]) -> str:
    name = os.path.basename(name or "")
    name = re.sub(r"[^\w.\-]+", "_", name)[:120]
    return name or "pasted-headers.txt"


class EvidenceStore:
    def __init__(self, base_dir):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def case_dir(self, case_id: str) -> Path:
        return self.base / validate_case_id(case_id)

    def store_original(self, case_id: str, raw: bytes, original_filename: str,
                       received_at: datetime, input_method: str) -> dict:
        case = self.case_dir(case_id)
        evidence = case / "evidence"
        evidence.mkdir(parents=True, exist_ok=False)
        (case / "derived").mkdir()
        original = evidence / "original.eml"
        original.write_bytes(raw)
        os.chmod(original, stat.S_IRUSR | stat.S_IRGRP)  # read-only
        manifest = {
            "case_id": case_id,
            "sha256": sha256_hex(raw),
            "size_bytes": len(raw),
            "original_filename": safe_filename(original_filename),
            "input_method": input_method,
            "received_at_utc": received_at.isoformat(),
            "tool_version": __version__,
        }
        (evidence / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def load_manifest(self, case_id: str) -> dict:
        path = self.case_dir(case_id) / "evidence" / "manifest.json"
        if not path.exists():
            raise EvidenceError(f"Case {case_id} not found.")
        return json.loads(path.read_text(encoding="utf-8"))

    def read_original(self, case_id: str) -> bytes:
        return (self.case_dir(case_id) / "evidence" / "original.eml").read_bytes()

    def verify(self, case_id: str) -> dict:
        manifest = self.load_manifest(case_id)
        current = sha256_hex(self.read_original(case_id))
        return {
            "expected_sha256": manifest["sha256"],
            "current_sha256": current,
            "intact": current == manifest["sha256"],
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        }

    def save_derived(self, case_id: str, name: str, data) -> Path:
        if not re.match(r"^[\w.\-]+$", name):
            raise EvidenceError(f"Invalid derived file name {name!r}")
        path = self.case_dir(case_id) / "derived" / name
        if isinstance(data, (bytes, bytearray)):
            path.write_bytes(data)
        else:
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def load_derived(self, case_id: str, name: str = "analysis.json") -> dict:
        path = self.case_dir(case_id) / "derived" / name
        if not path.exists():
            raise EvidenceError(f"No {name} for case {case_id}.")
        return json.loads(path.read_text(encoding="utf-8"))


# ============================================================================
# Part B - PDF report
# ============================================================================

SEVERITY_COLOURS = {"high": colors.HexColor("#b42318"), "medium": colors.HexColor("#b54708"),
                    "low": colors.HexColor("#175cd3"), "info": colors.HexColor("#475467")}
STATUS_COLOURS = {"pass": colors.HexColor("#067647"), "fail": colors.HexColor("#b42318"),
                  "neutral": colors.HexColor("#475467"), "missing": colors.HexColor("#475467"),
                  "inconclusive": colors.HexColor("#b54708")}

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=_styles["Heading1"], fontSize=17, spaceAfter=4)
H2 = ParagraphStyle("H2", parent=_styles["Heading2"], fontSize=12.5, spaceBefore=10,
                    spaceAfter=4, textColor=colors.HexColor("#101828"))
H3 = ParagraphStyle("H3", parent=_styles["Heading3"], fontSize=10, spaceBefore=6, spaceAfter=2)
BODY = ParagraphStyle("Body", parent=_styles["BodyText"], fontSize=8.6, leading=11,
                      alignment=TA_LEFT)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=7.4, leading=9.2)
CELL = ParagraphStyle("Cell", parent=BODY, fontSize=7.6, leading=9.4)
MONO = ParagraphStyle("Mono", parent=BODY, fontName="Courier", fontSize=6.6, leading=8)


def p(text, style=BODY) -> Paragraph:
    """Paragraph with all untrusted text escaped (ReportLab parses markup)."""
    return Paragraph(escape("" if text is None else str(text)), style)


def _cell(text, max_len: int = 400) -> Paragraph:
    text = "" if text is None else str(text)
    if len(text) > max_len:
        text = text[:max_len] + " ..."
    return p(text, CELL)


def _table(rows: List[list], widths, header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")))
    table.setStyle(TableStyle(style))
    return table


def _kv_table(pairs, width) -> Table:
    return _table([[_cell(k), _cell(v, 600)] for k, v in pairs],
                  [width * 0.28, width * 0.72], header=False)


def _coloured(text: str, colour) -> Paragraph:
    return Paragraph(f'<font color="{colour.hexval()}"><b>{escape(text)}</b></font>', CELL)


def _fmt_addrs(addrs) -> str:
    out = []
    for a in addrs or []:
        out.append(f'"{a["display_name"]}" <{a["address"]}>' if a.get("display_name")
                   else f'<{a["address"]}>')
    return ", ".join(out) or "-"


def build_report(analysis: dict, integrity: Optional[dict] = None,
                 manifest: Optional[dict] = None) -> bytes:
    meta = analysis["metadata"]
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Email forensic report {meta['case_id']}",
                            author=f"{meta['tool']} {meta['tool_version']}")
    width = doc.width
    story = []
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # ------------------------------------------------------------ case summary
    story.append(p("Email Forensic Analysis Report", H1))
    story.append(p(f"Case {meta['case_id']} - generated {generated}", SMALL))
    story.append(Spacer(1, 6))
    evidence = analysis["evidence"]
    pairs = [
        ("Case identifier", meta["case_id"]),
        ("Analysis time (UTC)", meta["analysis_time_utc"]),
        ("Report generated (UTC)", generated),
        ("Tool", f"{meta['tool']} v{meta['tool_version']}"),
        ("Source", (manifest or {}).get("original_filename") or meta.get("source_name") or "-"),
        ("Input method", (manifest or {}).get("input_method", "-")),
        ("Evidence size", f"{evidence['size_bytes']} bytes"),
        ("SHA-256 (at intake)", evidence["sha256"]),
    ]
    if integrity:
        pairs.append(("Integrity re-check",
                      ("INTACT - stored original matches the intake hash"
                       if integrity["intact"] else
                       f"MISMATCH - stored original now hashes to {integrity['current_sha256']}")
                      + f" (verified {integrity['verified_at_utc']})"))
    settings = meta["settings"]
    pairs.append(("Analysis settings",
                  f"scoring={settings['scoring_approach']}; "
                  f"trusted domains={settings['trusted_domains'] or 'auto'}; "
                  f"trusted authserv-ids={settings['trusted_authserv_ids'] or 'auto'}; "
                  f"extra protected domains={settings['protected_domains'] or 'none'}; "
                  f"DNS lookups={'on' if settings['dns_lookups'] else 'off'}; "
                  f"clock-skew tolerance={settings['clock_skew_minutes']} min"))
    story.append(_kv_table(pairs, width))

    # ------------------------------------------------------------ risk summary
    risk = analysis["risk"]
    story.append(p("1. Risk assessment", H2))
    colour = SEVERITY_COLOURS.get(risk["category"], colors.black)
    story.append(Paragraph(
        f'Category: <font color="{colour.hexval()}"><b>{escape(risk["category"].upper())}</b></font>'
        f" &nbsp; Score: <b>{risk['score']:g}</b> &nbsp; Approach: {escape(risk['approach'])}"
        + (f" (thresholds medium &ge; {risk['thresholds'][0]:g}, high &ge; {risk['thresholds'][1]:g})"
           if risk.get("thresholds") else ""), BODY))
    story.append(p(risk["disclaimer"], SMALL))
    if risk["contributions"]:
        rows = [[_cell("Rule"), _cell("Finding"), _cell("Severity"), _cell("Points"),
                 _cell("Why these points")]]
        for c in risk["contributions"]:
            rows.append([_cell(c["rule_id"]), _cell(c["title"]),
                         _coloured(c["severity"], SEVERITY_COLOURS[c["severity"]]),
                         _cell(f"{c['points']:g}"), _cell(c["explanation"])])
        story.append(Spacer(1, 4))
        story.append(_table(rows, [width * x for x in (0.26, 0.31, 0.1, 0.07, 0.26)]))
    else:
        story.append(p("No scored findings.", BODY))
    for note in risk.get("confidence_notes", []):
        story.append(p(f"Confidence note: {note}", SMALL))

    # ------------------------------------------------------------ headers
    parsed = analysis["parsed"]
    story.append(p("2. Extracted header information", H2))
    rp = parsed.get("return_path")
    story.append(_kv_table([
        ("From", _fmt_addrs(parsed["from_addrs"])),
        ("Sender", _fmt_addrs(parsed["sender"])),
        ("Reply-To", _fmt_addrs(parsed["reply_to"])),
        ("Return-Path", "<> (null sender)" if parsed["return_path_null"]
         else (f"<{rp['address']}>" if rp else "-")),
        ("To", _fmt_addrs(parsed["to_addrs"])),
        ("Cc", _fmt_addrs(parsed["cc_addrs"])),
        ("Subject", parsed.get("subject") or "-"),
        ("Date", f"{parsed.get('date_raw') or '-'} (parsed: {parsed.get('date') or 'unparseable'})"),
        ("Message-ID", parsed.get("message_id") or "-"),
        ("Domains observed", ", ".join(parsed.get("domains", [])) or "-"),
        ("IP addresses", ", ".join(f"{i['ip']} ({i['scope']})" for i in parsed["ips"]) or "-"),
        ("Header fields", f"{len(parsed['headers'])} total; "
                          f"{len(parsed['received'])} Received; "
                          f"{'headers only' if parsed['headers_only'] else 'full message'}"),
    ], width))
    if parsed["issues"]:
        story.append(p("Header issues", H3))
        rows = [[_cell("Field"), _cell("Type"), _cell("Severity"), _cell("Detail")]]
        for i in parsed["issues"]:
            rows.append([_cell(i["field"]), _cell(i["kind"]), _cell(i["severity"]),
                         _cell(i["detail"])])
        story.append(_table(rows, [width * x for x in (0.16, 0.16, 0.1, 0.58)]))

    # ------------------------------------------------------------ route
    route = analysis["route"]
    story.append(p("3. Apparent delivery route (earliest first)", H2))
    story.append(p(
        f"Trusted infrastructure: {', '.join(route['trusted_domains']) or 'none identified'}. "
        f"Origin IP seen by trusted server: {route['origin_ip'] or 'unknown'}"
        f"{' (' + route['origin_ip_scope'] + ')' if route.get('origin_ip_scope') else ''}. "
        "Hops marked 'claimed' were written by servers outside the trust boundary and "
        "may be forged.", BODY))
    if route["hops"]:
        rows = [[_cell("#"), _cell("From (HELO / rDNS / IP)"), _cell("By"),
                 _cell("Timestamp"), _cell("Delay"), _cell("Trust")]]
        for h in route["hops"]:
            delay = "-" if h["delay_seconds"] is None else f"{h['delay_seconds']:+.0f} s"
            rows.append([
                _cell(h["delivery_index"]),
                _cell(" / ".join(x for x in (h["from_helo"], h["from_rdns"], h["from_ip"]) if x) or "-"),
                _cell(h["by_host"] or "-"), _cell(h["timestamp"] or h["timestamp_raw"] or "-"),
                _cell(delay), _cell("trusted" if h["trusted"] else "claimed")])
        story.append(_table(rows, [width * x for x in (0.05, 0.34, 0.22, 0.2, 0.09, 0.1)]))
    for a in route["anomalies"]:
        story.append(p(f"[{a['severity']}] {a['kind']}: {a['detail']}", SMALL))

    # ------------------------------------------------------------ authentication
    auth = analysis["authentication"]
    story.append(p("4. Authentication results", H2))
    rows = [[_cell("Mechanism"), _cell("Status"), _cell("Reported"), _cell("Domain"),
             _cell("Interpretation")]]
    for key in ("spf", "dkim", "dmarc", "arc"):
        m = auth.get(key)
        if not m:
            continue
        rows.append([_cell(key.upper()), _coloured(m["status"], STATUS_COLOURS.get(
            m["status"], colors.black)), _cell(m["raw_result"] or "-"),
            _cell(m["domain"] or "-"), _cell(m["explanation"])])
    story.append(_table(rows, [width * x for x in (0.1, 0.1, 0.1, 0.18, 0.52)]))
    al = auth["alignment"]
    story.append(p(
        f"Alignment (computed): From={al['from_domain']}, SPF domain={al['spf_domain']} "
        f"(aligned: {al['spf_aligned']}), DKIM pass domains={', '.join(al['dkim_domains']) or 'none'} "
        f"(aligned: {al['dkim_aligned']}). {al['note']}", SMALL))
    story.append(p(f"Trusted authserv-ids: {', '.join(auth['trusted_authserv_ids']) or 'none'}; "
                   f"untrusted results ignored: {auth['untrusted_result_count']}.", SMALL))
    if auth.get("dns"):
        story.append(p("DNS (current state): " + "; ".join(
            f"{k}={v}" for k, v in auth["dns"].items()), SMALL))

    # ------------------------------------------------------------ findings
    story.append(p("5. Findings", H2))
    findings = analysis["findings"]
    if not findings:
        story.append(p("No suspicious indicators were found. This does not prove the "
                       "message is legitimate.", BODY))
    for n, f in enumerate(findings, 1):
        colour = SEVERITY_COLOURS[f["severity"]]
        block = [Paragraph(
            f'<b>{n}. {escape(f["title"])}</b> &nbsp; '
            f'<font color="{colour.hexval()}">[{escape(f["severity"].upper())}]</font> '
            f'<font size="7" color="#667085">{escape(f["rule_id"])}</font>', BODY)]
        block += [p(f"Evidence: {e}", SMALL) for e in f["evidence"]]
        block.append(p(f"Why it matters: {f['why_it_matters']}", SMALL))
        block.append(p(f"Limitations: {f['limitations']}", SMALL))
        if f.get("mitigated_by"):
            block.append(p("Mitigating context: " + "; ".join(f["mitigated_by"]), SMALL))
        block.append(Spacer(1, 4))
        story.append(KeepTogether(block))

    # ------------------------------------------------------------ limitations
    story.append(p("6. Limitations", H2))
    for item in analysis["limitations"]:
        story.append(p(f"- {item}", BODY))
    story.append(p("7. Recommended next steps", H2))
    for item in analysis["next_steps"]:
        story.append(p(f"- {item}", BODY))

    # ------------------------------------------------------------ appendix
    story.append(PageBreak())
    story.append(p("Appendix A - Header fields as parsed (unfolded, in original order)", H2))
    story.append(p("Control characters are shown as U+FFFD and very long values are "
                   "truncated. The unmodified original is preserved separately under "
                   "the SHA-256 above.", SMALL))
    lines = []
    for name, value in parsed["headers"]:
        wrapped = textwrap.wrap(f"{name}: {value}", 118, subsequent_indent="    ",
                                break_long_words=True) or [f"{name}:"]
        lines.extend(wrapped)
    story.append(Preformatted("\n".join(lines), MONO))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(16 * mm, 9 * mm,
                          f"{meta['case_id']}  |  SHA-256 {evidence['sha256']}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
