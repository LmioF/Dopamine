import pathlib
import unittest

from port_review_tracking import validate_tracking


VALID_REPORT = """# Review

#### Progress snapshot - 2026-09-15

| Tracking state | Count |
| --- | ---: |
| Findings with a previously recorded resolution, not rerun in this continuation | 1 |
| Open findings with implementation or fixture work recorded | 1 |
| Open findings still marked pending | 1 |
| Total numbered findings | 3 |
| Separate validation gaps, all open | 2 |

The previously recorded resolutions are PR-001. There are 2 open findings.
There are **3 numbered findings/risks**.

## 4. Current findings

### PR-001 - P2 - First

- [x] **Resolution:** previously verified; evidence is recorded here.

### PR-002 - P2 - Second

- [ ] **Resolution:** implementation recorded; verification pending.

### PR-003 - P2 - Third

- [ ] **Resolution:** pending; no implementation-phase fix or verification recorded.

## 5. Already corrected defects and counter-evidence

Historical findings are not extra resolution items.

## 6. Open hypotheses and validation gaps

- [ ] **V-01:** first validation.
- [ ] **V-02:** second validation.

| Gap | Exact question to resolve | Evidence required |
| --- | --- | --- |
| V-01: first validation | Question one | Evidence one |
| V-02: second validation | Question two | Evidence two |

## 7. Coverage and limitations

No runtime qualification is implied.
"""


class PortReviewTrackingTests(unittest.TestCase):
    def reject(self, changed: str) -> None:
        self.assertNotEqual(changed, VALID_REPORT)
        with self.assertRaises(ValueError):
            validate_tracking(changed)

    def test_valid_report(self):
        self.assertEqual(validate_tracking(VALID_REPORT), {
            "findings": 3,
            "closed": 1,
            "open": 2,
            "open_with_work": 1,
            "pending": 1,
            "validation_gaps": 2,
            "validation_open": 2,
        })

    def test_current_resolution_wording(self):
        changed = VALID_REPORT.replace(
            "Findings with a previously recorded resolution, not rerun in this continuation",
            "Findings with a recorded resolution",
        ).replace("The previously recorded resolutions are", "The recorded resolutions are")
        self.assertEqual(validate_tracking(changed), validate_tracking(VALID_REPORT))

    def test_duplicate_old_and_current_resolution_rows(self):
        self.reject(VALID_REPORT.replace(
            "| Open findings with implementation or fixture work recorded | 1 |",
            "| Findings with a recorded resolution | 1 |\n| Open findings with implementation or fixture work recorded | 1 |",
        ))

    def test_live_report(self):
        path = pathlib.Path(__file__).resolve().parents[1] / "PORT_REVIEW.md"
        counts = validate_tracking(path.read_text(encoding="utf-8"))
        self.assertGreater(counts["findings"], 0)
        self.assertEqual(counts["closed"] + counts["open"], counts["findings"])

    def test_duplicate_finding_id(self):
        self.reject(VALID_REPORT.replace("### PR-003", "### PR-002"))

    def test_missing_finding_id(self):
        self.reject(VALID_REPORT.replace("### PR-002", "### PR-004"))

    def test_missing_resolution_checkbox(self):
        self.reject(VALID_REPORT.replace("- [x] **Resolution:**", "**Resolution:**"))

    def test_duplicate_resolution_checkbox(self):
        self.reject(VALID_REPORT.replace("### PR-002", "- [x] **Resolution:** duplicate.\n\n### PR-002"))

    def test_empty_resolution(self):
        self.reject(VALID_REPORT.replace("previously verified; evidence is recorded here.", ""))

    def test_pending_finding_cannot_be_closed(self):
        self.reject(VALID_REPORT.replace("previously verified; evidence is recorded here.", "pending; no fix recorded."))

    def test_invalid_checkbox_marker(self):
        self.reject(VALID_REPORT.replace("- [x] **Resolution:**", "- [?] **Resolution:**"))

    def test_stale_total(self):
        self.reject(VALID_REPORT.replace("| Total numbered findings | 3 |", "| Total numbered findings | 4 |"))

    def test_stale_closed_total(self):
        self.reject(VALID_REPORT.replace("not rerun in this continuation | 1 |", "not rerun in this continuation | 2 |"))

    def test_stale_pending_total(self):
        self.reject(VALID_REPORT.replace("still marked pending | 1 |", "still marked pending | 0 |"))

    def test_stale_work_total(self):
        self.reject(VALID_REPORT.replace("fixture work recorded | 1 |", "fixture work recorded | 2 |"))

    def test_missing_summary_row(self):
        self.reject(VALID_REPORT.replace("| Total numbered findings | 3 |\n", ""))

    def test_duplicate_summary_row(self):
        self.reject(VALID_REPORT.replace("| Total numbered findings | 3 |", "| Total numbered findings | 3 |\n| Total numbered findings | 3 |"))

    def test_stale_closed_id_list(self):
        self.reject(VALID_REPORT.replace("resolutions are PR-001.", "resolutions are PR-002."))

    def test_stale_open_narrative(self):
        self.reject(VALID_REPORT.replace("There are 2 open findings.", "There are 1 open findings."))

    def test_stale_priority_total(self):
        self.reject(VALID_REPORT.replace("**3 numbered findings/risks**", "**4 numbered findings/risks**"))

    def test_missing_validation_checkbox(self):
        self.reject(VALID_REPORT.replace("- [ ] **V-02:** second validation.\n", ""))

    def test_duplicate_validation_checkbox(self):
        self.reject(VALID_REPORT.replace("- [ ] **V-02:**", "- [ ] **V-01:**"))

    def test_missing_validation_row(self):
        self.reject(VALID_REPORT.replace("| V-02: second validation | Question two | Evidence two |\n", ""))

    def test_duplicate_validation_row(self):
        self.reject(VALID_REPORT.replace("| V-02: second validation", "| V-01: second validation"))

    def test_stale_validation_total(self):
        self.reject(VALID_REPORT.replace("| Separate validation gaps, all open | 2 |", "| Separate validation gaps, all open | 3 |"))

    def test_closed_validation_contradicts_all_open(self):
        self.reject(VALID_REPORT.replace("- [ ] **V-02:**", "- [x] **V-02:**"))

    def test_historical_mentions_do_not_add_findings(self):
        changed = VALID_REPORT.replace("Historical findings are not extra resolution items.", "PR-001 and PR-001 are historical references, not new findings.")
        self.assertEqual(validate_tracking(changed), validate_tracking(VALID_REPORT))

    def test_inline_section_reference_does_not_truncate_snapshot(self):
        changed = "See ## 4. Current findings for details.\n\n" + VALID_REPORT
        self.assertEqual(validate_tracking(changed), validate_tracking(VALID_REPORT))

    def test_missing_findings_section(self):
        self.reject(VALID_REPORT.replace("## 4. Current findings", "## Findings without the required section boundary"))

    def test_empty_document(self):
        self.reject("")


if __name__ == "__main__":
    unittest.main()
