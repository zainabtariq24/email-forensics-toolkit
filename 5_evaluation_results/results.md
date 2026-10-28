# Evaluation results

Generated 2026-10-28 19:00 UTC on 41 synthetic labelled cases (20 suspicious, 21 legitimate). Positive class = suspicious; predicted positive = risk category medium/high.

## 1. Approach comparison

| Approach | Split | n | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| severity_sum | tune | 25 | 12 | 1 | 11 | 1 | 0.923 | 0.923 | 0.923 |
| severity_sum | test | 16 | 7 | 2 | 7 | 0 | 0.778 | 1.000 | 0.875 |
| rule_weighted | tune | 25 | 11 | 2 | 10 | 2 | 0.846 | 0.846 | 0.846 |
| rule_weighted | test | 16 | 7 | 1 | 8 | 0 | 0.875 | 1.000 | 0.933 |
| max_severity | tune | 25 | 12 | 1 | 11 | 1 | 0.923 | 0.923 | 0.923 |
| max_severity | test | 16 | 7 | 2 | 7 | 0 | 0.778 | 1.000 | 0.875 |

**Selected on the tuning split:** `severity_sum` (highest tuning F1, ties broken by fewer false positives).

## 2. Held-out test split - `severity_sum`

| | Predicted suspicious | Predicted legitimate |
|---|---|---|
| **Labelled suspicious** | TP = 7 | FN = 0 |
| **Labelled legitimate** | FP = 2 | TN = 7 |

Precision 0.778, recall 1.000, F1 0.875.

## 3. Full dataset - `severity_sum`

| | Predicted suspicious | Predicted legitimate |
|---|---|---|
| **Labelled suspicious** | TP = 19 | FN = 1 |
| **Labelled legitimate** | FP = 3 | TN = 18 |

Precision 0.864, recall 0.950, F1 0.905.

## 4. Errors (all approaches)

**severity_sum** - 4 error(s)
- FP `L06_helpdesk_ticket.eml` (test, score 4.0, medium): rules SENDER-REPLYTO-MISMATCH, SENDER-RETURNPATH-MISMATCH
- FP `L08_mailing_list_dkim_broken.eml` (test, score 5.0, medium): rules AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, SENDER-RETURNPATH-MISMATCH
- FP `L11_forwarded_everything_broken.eml` (tune, score 5.0, medium): rules AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, AUTH-SPF-FAIL
- FN `S18_compromised_account.eml` (tune, score 0.0, low): rules none

**rule_weighted** - 5 error(s)
- FP `L07_mailing_list_rewritten.eml` (tune, score 2.8, medium): rules DOMAIN-LOOKALIKE, SENDER-REPLYTO-MISMATCH
- FP `L08_mailing_list_dkim_broken.eml` (test, score 4.0, medium): rules AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, SENDER-RETURNPATH-MISMATCH
- FP `L11_forwarded_everything_broken.eml` (tune, score 4.6, medium): rules AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, AUTH-SPF-FAIL
- FN `S15_unaligned_no_dmarc_recorded.eml` (tune, score 2.45, low): rules AUTH-NOT-ALIGNED, SENDER-RETURNPATH-MISMATCH
- FN `S18_compromised_account.eml` (tune, score 0.0, low): rules none

**max_severity** - 4 error(s)
- FP `L06_helpdesk_ticket.eml` (test, score 2.0, medium): rules SENDER-REPLYTO-MISMATCH, SENDER-RETURNPATH-MISMATCH
- FP `L08_mailing_list_dkim_broken.eml` (test, score 2.0, medium): rules AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, SENDER-RETURNPATH-MISMATCH
- FP `L11_forwarded_everything_broken.eml` (tune, score 2.0, medium): rules AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, AUTH-SPF-FAIL
- FN `S18_compromised_account.eml` (tune, score 0.0, low): rules none

## 5. Per-case results - `severity_sum`

| Case | Label | Split | Score | Category | Non-info rules |
|---|---|---|---|---|---|
| L01_personal_gmail.eml | legitimate | tune | 0.0 | low |  |
| L02_github_notification.eml | legitimate | test | 0.0 | low |  |
| L03_internal_department.eml | legitimate | tune | 0.0 | low |  |
| L04_bank_statement.eml | legitimate | test | 0.0 | low |  |
| L05_esp_newsletter.eml | legitimate | tune | 1.0 | low | SENDER-RETURNPATH-MISMATCH |
| L06_helpdesk_ticket.eml | legitimate | test | 4.0 | medium | SENDER-REPLYTO-MISMATCH, SENDER-RETURNPATH-MISMATCH |
| L07_mailing_list_rewritten.eml | legitimate | tune | 2.0 | low | DOMAIN-LOOKALIKE, SENDER-REPLYTO-MISMATCH |
| L08_mailing_list_dkim_broken.eml | legitimate | test | 5.0 | medium | AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, SENDER-RETURNPATH-MISMATCH |
| L09_forwarded_spf_fail.eml | legitimate | tune | 1.0 | low | AUTH-SPF-FAIL |
| L10_forwarded_softfail_arc.eml | legitimate | test | 1.0 | low | AUTH-SPF-FAIL |
| L11_forwarded_everything_broken.eml | legitimate | tune | 5.0 | medium | AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, AUTH-SPF-FAIL |
| L12_microsoft365_style.eml | legitimate | tune | 0.0 | low |  |
| L13_calendar_invite.eml | legitimate | test | 0.0 | low |  |
| L14_amazon_ses.eml | legitimate | tune | 0.0 | low |  |
| L15_paypal_genuine.eml | legitimate | test | 0.0 | low |  |
| L16_small_business_no_dmarc.eml | legitimate | tune | 0.0 | low |  |
| L17_queued_delivery.eml | legitimate | test | 0.0 | low |  |
| L18_custom_domain_via_gmail.eml | legitimate | tune | 0.0 | low |  |
| L19_clock_skew.eml | legitimate | test | 0.0 | low |  |
| L20_autoreply_null_sender.eml | legitimate | tune | 0.0 | low |  |
| L21_internal_scanner.eml | legitimate | tune | 2.0 | low | AUTH-MISSING, HEADER-MISSING |
| S01_lookalike_digit.eml | suspicious | tune | 9.0 | high | DOMAIN-LOOKALIKE, SENDER-DISPLAYNAME-BRAND |
| S02_displayname_brand_freemail.eml | suspicious | tune | 6.0 | high | SENDER-DISPLAYNAME-BRAND |
| S03_exact_domain_spoof.eml | suspicious | tune | 9.0 | high | AUTH-DMARC-FAIL, AUTH-SPF-FAIL |
| S04_bec_freemail_replyto.eml | suspicious | test | 11.0 | high | AUTH-DMARC-FAIL, AUTH-SPF-FAIL, SENDER-REPLYTO-MISMATCH, SENDER-RETURNPATH-MISMATCH |
| S05_bec_lookalike_replyto.eml | suspicious | test | 9.0 | high | DOMAIN-INTERNAL-LOOKALIKE, SENDER-REPLYTO-MISMATCH |
| S06_idn_homograph.eml | suspicious | tune | 9.0 | high | DOMAIN-LOOKALIKE, SENDER-DISPLAYNAME-BRAND |
| S07_brand_embedded.eml | suspicious | test | 9.0 | high | DOMAIN-LOOKALIKE, SENDER-DISPLAYNAME-BRAND |
| S08_brand_in_subdomain.eml | suspicious | tune | 9.0 | high | DOMAIN-LOOKALIKE, SENDER-DISPLAYNAME-BRAND |
| S09_displayname_address.eml | suspicious | tune | 6.0 | high | SENDER-DISPLAYNAME-ADDRESS |
| S10_duplicate_from.eml | suspicious | tune | 14.0 | high | AUTH-DMARC-FAIL, HEADER-DUPLICATE, HEADER-MALFORMED, SENDER-RETURNPATH-MISMATCH |
| S11_forged_auth_results.eml | suspicious | test | 13.0 | high | AUTH-DMARC-FAIL, AUTH-SPF-FAIL, AUTH-UNTRUSTED-CLAIMS, SENDER-RETURNPATH-MISMATCH |
| S12_forged_received_chain.eml | suspicious | tune | 10.0 | high | AUTH-DMARC-FAIL, ROUTE-INCONSISTENT, SENDER-RETURNPATH-MISMATCH |
| S13_spf_dmarc_fail_bank.eml | suspicious | tune | 10.0 | high | AUTH-DMARC-FAIL, AUTH-SPF-FAIL, SENDER-RETURNPATH-MISMATCH |
| S14_dkim_fail_courier.eml | suspicious | test | 13.0 | high | AUTH-DKIM-FAIL, AUTH-DMARC-FAIL, AUTH-SPF-FAIL, SENDER-RETURNPATH-MISMATCH |
| S15_unaligned_no_dmarc_recorded.eml | suspicious | tune | 4.0 | medium | AUTH-NOT-ALIGNED, SENDER-RETURNPATH-MISMATCH |
| S16_typosquat.eml | suspicious | test | 9.0 | high | DOMAIN-LOOKALIKE, SENDER-DISPLAYNAME-BRAND |
| S17_handcrafted_malformed.eml | suspicious | test | 9.0 | high | AUTH-MISSING, HEADER-MALFORMED, HEADER-MISSING, ROUTE-MISSING, SENDER-REPLYTO-MISMATCH |
| S18_compromised_account.eml | suspicious | tune | 0.0 | low |  |
| S19_org_lookalike.eml | suspicious | tune | 6.0 | high | DOMAIN-LOOKALIKE |
| S20_hostile_encoded.eml | suspicious | tune | 10.0 | high | AUTH-DMARC-FAIL, AUTH-SPF-FAIL, SENDER-RETURNPATH-MISMATCH |

## 6. Caveats

- The dataset is small and synthetic, and was written by the same author as the rules. These numbers show the rules behave as designed on these scenarios; they do **not** establish real-world accuracy.
- The tuning/test split only separates the choice of approach from the final measurement; weights were set by hand as hypotheses.
- Header analysis cannot detect phishing sent from a genuinely compromised account (see S18) or judge message content.
- Add messages you own or are authorised to analyse to `dataset/emails/` and `test_cases.csv` to obtain a more realistic estimate.
