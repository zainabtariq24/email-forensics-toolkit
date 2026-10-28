import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "1_forensic_analysis_modules"))
sys.path.insert(0, str(ROOT / "2_web_interface"))

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def make_email(*header_lines: str, body: str = "Body text\n") -> bytes:
    """Join header lines into a raw message (CRLF, blank line, body)."""
    return ("\r\n".join(header_lines) + "\r\n\r\n" + body).encode("utf-8")


BASIC = [
    "Received: from mx1.uni-example.edu (mx1.uni-example.edu [10.0.0.5]) "
    "by mailbox.uni-example.edu with LMTP id 1; Mon, 14 Sep 2026 09:30:10 +0000",
    "Authentication-Results: mx1.uni-example.edu; spf=pass smtp.mailfrom=sender.com; "
    "dkim=pass header.d=sender.com; dmarc=pass header.from=sender.com",
    "Received: from mail.sender.com (mail.sender.com [81.2.69.160]) "
    "by mx1.uni-example.edu with ESMTPS id 2; Mon, 14 Sep 2026 09:30:00 +0000",
    "Return-Path: <bounce@sender.com>",
    'From: "Alice Sender" <alice@sender.com>',
    "To: <bob@uni-example.edu>",
    "Subject: Hello",
    "Date: Mon, 14 Sep 2026 09:29:30 +0000",
    "Message-ID: <abc123@sender.com>",
]


@pytest.fixture
def basic_raw():
    return make_email(*BASIC)


def replace_header(lines, prefix, new_line):
    """Return a copy of header lines with the line starting with prefix replaced
    (or removed when new_line is None)."""
    out = []
    for line in lines:
        if line.startswith(prefix):
            if new_line is not None:
                out.append(new_line)
        else:
            out.append(line)
    return out
