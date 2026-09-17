"""Validate report bookkeeping without importing or executing project code."""

import json
import pathlib
import re
import sys


def section(document: str, start: str, end: str) -> str:
    starts = list(re.finditer(r"^" + re.escape(start) + r"$", document, re.MULTILINE))
    ends = list(re.finditer(r"^" + re.escape(end) + r"$", document, re.MULTILINE))
    if len(starts) != 1 or len(ends) != 1 or starts[0].end() >= ends[0].start():
        raise ValueError(f"Missing, duplicated or reordered section: {start}")
    return document[starts[0].end():ends[0].start()]


def require_count(text: str, pattern: str, expected: int, label: str) -> None:
    values = re.findall(pattern, text, re.MULTILINE)
    if len(values) != 1 or int(values[0]) != expected:
        raise ValueError(f"Missing, duplicated or stale {label}; expected {expected}")


def validate_tracking(document: str) -> dict[str, int]:
    findings = section(document, "## 4. Current findings", "## 5. Already corrected defects and counter-evidence")
    headers = list(re.finditer(r"^### (PR-\d{3}) - [^\n]+$", findings, re.MULTILINE))
    identifiers = [match.group(1) for match in headers]
    expected_ids = [f"PR-{index:03d}" for index in range(1, len(headers) + 1)]
    if not headers or identifiers != expected_ids:
        raise ValueError("Finding IDs must be unique and consecutive from PR-001")

    closed_ids = []
    pending = 0
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(findings)
        body = findings[header.end():end]
        resolution_lines = re.findall(r"^.*\*\*Resolution:\*\*.*$", body, re.MULTILINE)
        boxes = re.findall(r"^- \[([ xX])\] \*\*Resolution:\*\*[ \t]*(.*)$", body, re.MULTILINE)
        if len(resolution_lines) != 1 or len(boxes) != 1 or not boxes[0][1].strip():
            raise ValueError(f"{header.group(1)} needs exactly one nonempty resolution checkbox")
        marker, description = boxes[0]
        is_pending = re.match(r"pending\b", description.strip(), re.IGNORECASE) is not None
        if marker.lower() == "x":
            if is_pending:
                raise ValueError(f"{header.group(1)} is checked but still marked pending")
            closed_ids.append(header.group(1))
        elif is_pending:
            pending += 1

    validation = section(document, "## 6. Open hypotheses and validation gaps", "## 7. Coverage and limitations")
    gap_boxes = re.findall(r"^- \[([ xX])\] \*\*(V-\d{2}):\*\* [^\n]+$", validation, re.MULTILINE)
    gap_rows = re.findall(r"^\| (V-\d{2}): [^\n]+$", validation, re.MULTILINE)
    gap_ids = [identifier for _, identifier in gap_boxes]
    expected_gaps = [f"V-{index:02d}" for index in range(1, len(gap_rows) + 1)]
    if not gap_rows or gap_ids != expected_gaps or gap_rows != expected_gaps:
        raise ValueError("Validation checkboxes and matrix rows must have matching unique consecutive IDs")

    counts = {
        "findings": len(headers),
        "closed": len(closed_ids),
        "open": len(headers) - len(closed_ids),
        "open_with_work": len(headers) - len(closed_ids) - pending,
        "pending": pending,
        "validation_gaps": len(gap_rows),
        "validation_open": sum(marker == " " for marker, _ in gap_boxes),
    }

    snapshot = re.split(r"^## 4\. Current findings$", document, maxsplit=1, flags=re.MULTILINE)[0]
    require_count(snapshot, r"^\| Findings with (?:a recorded resolution|a previously recorded resolution, not rerun in this continuation) \| (\d+) \|$", counts["closed"], "recorded-resolution total")
    labels = {
        "Open findings with implementation or fixture work recorded": "open_with_work",
        "Open findings still marked pending": "pending",
        "Total numbered findings": "findings",
    }
    for label, key in labels.items():
        require_count(snapshot, r"^\| " + re.escape(label) + r" \| (\d+) \|$", counts[key], label)
    require_count(snapshot, r"^\| Separate validation gaps(?:, all open)? \| (\d+) \|$", counts["validation_gaps"], "validation total")
    if "| Separate validation gaps, all open |" in snapshot and counts["validation_open"] != counts["validation_gaps"]:
        raise ValueError("The snapshot says all validation gaps are open, but a gap is checked")

    lists = re.findall(r"The (?:previously )?recorded resolutions are ([^\n]*?)\.", snapshot)
    if len(lists) != 1 or re.findall(r"PR-\d{3}", lists[0]) != closed_ids:
        raise ValueError("The previously recorded resolution list does not match the checked findings")
    require_count(snapshot, r"There are (\d+) open findings\.", counts["open"], "open-finding narrative")
    require_count(snapshot, r"There are \*\*(\d+) numbered findings/risks\*\*", counts["findings"], "priority-map total")
    return counts


def main() -> int:
    path = pathlib.Path(__file__).resolve().parents[1] / "PORT_REVIEW.md"
    try:
        counts = validate_tracking(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": "PASS", "scope": "report consistency only", **counts}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
