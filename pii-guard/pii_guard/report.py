"""스캔 결과 리포트 (Markdown).

리포트에는 마스킹된 `preview` 만 싣는다. 원본 값을 실으면 탐지 리포트 자체가
새로운 유출 경로가 된다.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .scanner import FileScan, aggregate

SEVERITY_MARK = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}


def build_markdown(scans: List[FileScan], title: str = "개인정보 탐지 스캔 리포트") -> str:
    stats = aggregate(scans)
    totals = stats["totals"]
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# {}".format(title),
        "",
        "생성 {} · 파일 {}개 스캔".format(stamp, stats["files_scanned"]),
        "",
        "## 총계",
        "",
        "| 등급 | 건수 |",
        "|---|---|",
    ]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append("| {} {} | {} |".format(
            SEVERITY_MARK[severity], severity, totals.get(severity, 0)))
    lines += ["| **합계** | **{}** |".format(totals.get("total", 0)), ""]

    lines += ["## 데이터 클래스별", "",
              "| 데이터 클래스 | 파일 | 탐지된 파일 | CRITICAL | HIGH | MEDIUM | LOW |",
              "|---|---|---|---|---|---|---|"]
    for name, bucket in stats["by_class"].items():
        lines.append("| `{}` | {} | {} | {} | {} | {} | {} |".format(
            name, bucket["files"], bucket["files_with_findings"],
            bucket.get("CRITICAL", 0), bucket.get("HIGH", 0),
            bucket.get("MEDIUM", 0), bucket.get("LOW", 0)))
    lines.append("")

    if stats["by_rule"]:
        lines += ["## 규칙별", "", "| 규칙 | 항목 | 등급 | 건수 |", "|---|---|---|---|"]
        for rule_id, entry in stats["by_rule"].items():
            lines.append("| `{}` | {} | {} {} | {} |".format(
                rule_id, entry["label"],
                SEVERITY_MARK.get(entry["severity"], ""), entry["severity"], entry["count"]))
        lines.append("")

    hits = [scan for scan in scans if scan.findings]
    if hits:
        lines += ["## 파일별 상세", "",
                  "> 값은 마스킹되어 있다. 리포트가 또 하나의 유출 경로가 되지 않게 하기 위해서다.",
                  ""]
        for scan in hits:
            lines.append("### `{}`".format(scan.path))
            lines.append("")
            lines.append("데이터 클래스: `{}`".format(scan.data_class))
            lines.append("")
            lines.append("| 규칙 | 등급 | 검증 | 마스킹된 값 |")
            lines.append("|---|---|---|---|")
            for finding in scan.findings:
                validated = {True: "통과", False: "실패(등급 하향)", None: "—"}[finding.validated]
                lines.append("| `{}` | {} {} | {} | `{}` |".format(
                    finding.rule_id, SEVERITY_MARK.get(finding.severity, ""),
                    finding.severity, validated, finding.preview))
            lines.append("")
    else:
        lines += ["## 파일별 상세", "", "탐지된 개인정보가 없다.", ""]

    return "\n".join(lines)


def save_markdown(scans: List[FileScan], path, title: str = "개인정보 탐지 스캔 리포트") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_markdown(scans, title), encoding="utf-8")
    return path


def build_payload(scans: List[FileScan]) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "aggregate": aggregate(scans),
        "files": [scan.to_dict() for scan in scans],
    }
