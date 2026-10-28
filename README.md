# Email Forensics Toolkit

A Python tool that parses email headers, reconstructs the apparent delivery
route, interprets SPF/DKIM/DMARC/ARC evidence, detects spoofing indicators,
produces an explainable risk assessment and generates integrity-aware PDF
forensic reports.

The toolkit identifies and explains evidence that supports or weakens a
hypothesis. It **does not** prove who sent a message or whether an account
was compromised.

## Getting started

Requires Python 3.9 or newer (macOS, Windows or Linux).

```bash
git clone https://github.com/zainabtariq24/email-forensics-toolkit.git
cd email-forensics-toolkit
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

| Task | Command |
|---|---|
| Start the web interface | `python 2_web_interface/app.py`, then open http://127.0.0.1:5050 |
| Run the 150 unit tests | `python -m pytest` |
| Re-run the evaluation | `python 1_forensic_analysis_modules/module7_evaluation.py` |
| Rebuild the test dataset | `python 4_labelled_test_emails/generate_dataset.py` |

## Project structure

Folders are numbered so they appear in presentation order: modules first,
then the GUI, then everything else.

```
email-forensics-toolkit/
├── 1_forensic_analysis_modules/
│   ├── module1_header_extraction.py     Module 1  parse .eml / pasted headers
│   ├── module2_route_reconstruction.py  Module 2  Received headers -> delivery route
│   ├── module3_authentication.py        Module 3  SPF, DKIM, DMARC, ARC
│   ├── module4_spoofing_detection.py    Module 4  look-alike domains + spoofing rules
│   ├── module5_risk_assessment.py       Module 5  three scoring approaches
│   ├── module6_forensic_report.py       Module 6  SHA-256 evidence store + PDF report
│   ├── module7_evaluation.py            Module 7  confusion matrix, precision, recall, F1
│   └── analyzer.py                      runs modules 1-5 in order, holds the settings
├── 2_web_interface/
│   ├── app.py                           Flask web interface
│   ├── templates/                       HTML pages
│   └── static/                          stylesheet, script, bundled fonts
├── 3_unit_tests/                         one test file per module (150 tests)
├── 4_labelled_test_emails/               41 labelled synthetic emails + generator
├── 5_evaluation_results/results.md       latest evaluation output
├── 6_sample_pdf_reports/                 example PDF reports
├── README.md, requirements.txt
└── cases/                               created at runtime: one folder per analysis
```

### How the pipeline flows

```
upload / paste (2_web_interface/app.py)
   │
   ▼
Module 6A  hash (SHA-256) and store the original read-only
   │
   ▼
Module 1  parse headers ──► Module 2  route + trust boundary ──► Module 3  SPF/DKIM/DMARC
                                                                     │
                                                                     ▼
Module 6B  PDF / JSON  ◄── Module 5  risk score  ◄── Module 4  findings (spoofing, look-alikes)
```

`1_forensic_analysis_modules/analyzer.py` runs this chain, and the GUI calls the analyzer.

### Evidence handling

Each submission is stored under `cases/<case-id>/` (created automatically):

```
evidence/original.eml     exact bytes received (read-only)
evidence/manifest.json    SHA-256, size, filename, input method, UTC time, tool version
derived/analysis.json     normalised and derived results
derived/report.pdf        generated report
```

Before the results page or a report is produced, the original is re-hashed.
The report states whether it still matches the intake hash.

### Trust model

The topmost Received header is written by the recipient's own server. By
default the tool trusts that server's organisation and the authserv-id in the
topmost Authentication-Results header, but only if that ID belongs to the same
organisation. Hops below the trust boundary are shown as *claimed*, and
authentication results from other servers are ignored. If an attacker inserts
a fake `Authentication-Results: mx.google.com; dmarc=pass` header, the tool
reports it (`AUTH-UNTRUSTED-CLAIMS`) and doesn't believe it.

## Dataset and evaluation

`4_labelled_test_emails/generate_dataset.py` builds 41 **synthetic** labelled messages: 21
legitimate and 20 suspicious. Cases alternate per category between a
**tuning** split, used only to choose the scoring approach, and a held-out
**test** split.

| Approach | Tune F1 | Test precision | Test recall | Test F1 |
|---|---|---|---|---|
| **severity_sum** (selected) | 0.923 | 0.778 | 1.000 | 0.875 |
| rule_weighted | 0.846 | 0.875 | 1.000 | 0.933 |
| max_severity | 0.923 | 0.778 | 1.000 | 0.875 |

`severity_sum` was selected on the tuning split (tied with `max_severity`). On
the 16-case test split, `rule_weighted` happened to score higher, which shows
how unstable small test sets are.

Error analysis:

- **False positives:** legitimate mail with real anomalies, namely a helpdesk
  Reply-To on another domain (L06), a mailing list that breaks DKIM/DMARC
  (L08) and a forwarder that breaks every check (L11).
- **False negative:** S18, phishing from a compromised account. Every header
  check passes, so header analysis cannot detect it.

**Limitations:** the dataset is small and synthetic, and the same team wrote
both the dataset and the rules. These numbers do not establish real-world
accuracy.

## Known limitations

- Signatures are not re-verified. The tool interprets what the receiving server recorded.
- The organisational domain uses a built-in suffix list, not the full Public Suffix List.
- Look-alike detection is heuristic and limited to the protected-domain list.
- Message bodies, URLs and attachments are not analysed.
- DNS lookups (optional) show the *current* records, which may differ from the records at delivery time.
- The Flask app is meant for local use. It binds to 127.0.0.1 and has no login or CSRF protection.
