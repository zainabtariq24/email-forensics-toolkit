"""Module 7 - Evaluate the detector on the labelled dataset.

Procedure (kept deliberately simple and reproducible):

1. Run every scoring approach on the TUNING split and pick the one with the
   best F1 (ties -> fewer false positives).
2. Report all approaches on the held-out TEST split, plus the chosen one on
   the full dataset, with confusion matrices and per-case outcomes.

"Positive" = labelled suspicious; the tool predicts positive when the risk
category is medium or high.

    python 1_forensic_analysis_modules/module7_evaluation.py    # writes 5_evaluation_results/results.md
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))  # 1_forensic_analysis_modules

from analyzer import AnalysisSettings, analyze_email  # noqa: E402
from module5_risk_assessment import APPROACHES  # noqa: E402

DATASET = ROOT / "4_labelled_test_emails"
OUT = ROOT / "5_evaluation_results"
# Fixed time so results do not drift as the calendar moves.
EVAL_TIME = datetime(2026, 10, 1, tzinfo=timezone.utc)
SETTINGS = dict(trusted_domains=["uni-example.edu"])


def load_cases():
    with open(DATASET / "test_cases.csv", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def metrics(rows):
    tp = sum(1 for r in rows if r["label"] == "suspicious" and r["flagged"])
    fp = sum(1 for r in rows if r["label"] == "legitimate" and r["flagged"])
    tn = sum(1 for r in rows if r["label"] == "legitimate" and not r["flagged"])
    fn = sum(1 for r in rows if r["label"] == "suspicious" and not r["flagged"])
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    return {"n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "accuracy": round(accuracy, 3)}


def run_approach(cases, approach):
    rows = []
    for case in cases:
        raw = (DATASET / "emails" / case["filename"]).read_bytes()
        result = analyze_email(raw, AnalysisSettings(scoring_approach=approach, **SETTINGS),
                               source_name=case["filename"], analysis_time=EVAL_TIME)
        risk = result["risk"]
        rows.append({**case, "flagged": risk["flagged"], "category": risk["category"],
                     "score": risk["score"],
                     "rules": sorted({f["rule_id"] for f in result["findings"]
                                      if f["severity"] != "info"})})
    return rows


def sklearn_crosscheck(rows):
    """Confirm the hand-written metrics with scikit-learn when it is installed."""
    try:
        from sklearn.metrics import confusion_matrix, f1_score
    except ImportError:
        return None
    y_true = [r["label"] == "suspicious" for r in rows]
    y_pred = [r["flagged"] for r in rows]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[False, True]).ravel()
    return {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 3)}


def confusion_table(m):
    return ("| | Predicted suspicious | Predicted legitimate |\n|---|---|---|\n"
            f"| **Labelled suspicious** | TP = {m['tp']} | FN = {m['fn']} |\n"
            f"| **Labelled legitimate** | FP = {m['fp']} | TN = {m['tn']} |\n")


def main():
    cases = load_cases()
    by_approach = {a: run_approach(cases, a) for a in APPROACHES}
    summary = {}
    for approach, rows in by_approach.items():
        summary[approach] = {
            split: metrics([r for r in rows if split == "all" or r["split"] == split])
            for split in ("tune", "test", "all")}

    chosen = max(APPROACHES, key=lambda a: (summary[a]["tune"]["f1"],
                                            -summary[a]["tune"]["fp"]))
    chosen_rows = by_approach[chosen]
    check = sklearn_crosscheck(chosen_rows)

    lines = [
        "# Evaluation results", "",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} on "
        f"{len(cases)} synthetic labelled cases "
        f"({sum(c['label'] == 'suspicious' for c in cases)} suspicious, "
        f"{sum(c['label'] == 'legitimate' for c in cases)} legitimate). "
        "Positive class = suspicious; predicted positive = risk category medium/high.",
        "",
        "## 1. Approach comparison", "",
        "| Approach | Split | n | TP | FP | TN | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for approach in APPROACHES:
        for split in ("tune", "test"):
            m = summary[approach][split]
            lines.append(f"| {approach} | {split} | {m['n']} | {m['tp']} | {m['fp']} | "
                         f"{m['tn']} | {m['fn']} | {m['precision']:.3f} | "
                         f"{m['recall']:.3f} | {m['f1']:.3f} |")
    lines += ["", f"**Selected on the tuning split:** `{chosen}` "
                  "(highest tuning F1, ties broken by fewer false positives).", "",
              f"## 2. Held-out test split - `{chosen}`", "",
              confusion_table(summary[chosen]["test"]),
              f"Precision {summary[chosen]['test']['precision']:.3f}, "
              f"recall {summary[chosen]['test']['recall']:.3f}, "
              f"F1 {summary[chosen]['test']['f1']:.3f}.", "",
              f"## 3. Full dataset - `{chosen}`", "",
              confusion_table(summary[chosen]["all"]),
              f"Precision {summary[chosen]['all']['precision']:.3f}, "
              f"recall {summary[chosen]['all']['recall']:.3f}, "
              f"F1 {summary[chosen]['all']['f1']:.3f}."
              + (f" scikit-learn cross-check: {check}." if check else ""), "",
              "## 4. Errors (all approaches)", ""]
    for approach in APPROACHES:
        errors = [r for r in by_approach[approach]
                  if r["flagged"] != (r["label"] == "suspicious")]
        lines.append(f"**{approach}** - {len(errors)} error(s)")
        for r in errors:
            kind = "FP" if r["flagged"] else "FN"
            lines.append(f"- {kind} `{r['filename']}` ({r['split']}, score {r['score']}, "
                         f"{r['category']}): rules {', '.join(r['rules']) or 'none'}")
        lines.append("")
    lines += [f"## 5. Per-case results - `{chosen}`", "",
              "| Case | Label | Split | Score | Category | Non-info rules |",
              "|---|---|---|---|---|---|"]
    for r in chosen_rows:
        lines.append(f"| {r['filename']} | {r['label']} | {r['split']} | {r['score']} | "
                     f"{r['category']} | {', '.join(r['rules'])} |")
    lines += ["", "## 6. Caveats", "",
              "- The dataset is small and synthetic, and was written by the same "
              "author as the rules. These numbers show the rules behave as designed "
              "on these scenarios; they do **not** establish real-world accuracy.",
              "- The tuning/test split only separates the choice of approach from "
              "the final measurement; weights were set by hand as hypotheses.",
              "- Header analysis cannot detect phishing sent from a genuinely "
              "compromised account (see S18) or judge message content.",
              "- Add messages you own or are authorised to analyse to "
              "`dataset/emails/` and `test_cases.csv` to obtain a more realistic estimate."]

    (OUT / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:4 + 2 + 2 * len(APPROACHES) + 4]))
    print(f"\nWrote {OUT / 'results.md'}")


if __name__ == "__main__":
    main()
