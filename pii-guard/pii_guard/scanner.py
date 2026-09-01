"""파일·디렉터리 단위 개인정보 스캐너.

통제가 걸린 뒤에도 **잔여 개인정보가 없는지** 확인하는 용도다.
탐지만 하고 원본 파일은 건드리지 않는다 (소급 정제는 별도 판단이 필요하다).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .detector import Finding, PIIDetector, summarize

# 스캔에서 제외할 경로. 산출물·가상환경·캐시를 훑으면 시간만 쓰고 잡음만 는다.
DEFAULT_EXCLUDES = ("__pycache__", ".git", ".venv", "venv", "node_modules", ".DS_Store")

TEXT_SUFFIXES = (".json", ".jsonl", ".log", ".txt", ".md", ".csv", ".py", ".yaml", ".yml")


@dataclass
class FileScan:
    """파일 한 개의 스캔 결과."""

    path: str
    data_class: str
    findings: List[Finding] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "data_class": self.data_class,
            "summary": summarize(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


class PIIScanner:
    """대상 경로를 훑어 탐지 결과를 모은다."""

    def __init__(self, detector: Optional[PIIDetector] = None,
                 excludes=DEFAULT_EXCLUDES):
        self.detector = detector or PIIDetector()
        self.excludes = tuple(excludes)

    def _iter_files(self, target: Path):
        if target.is_file():
            yield target
            return
        if not target.exists():
            return
        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            # 제외 판정은 **스캔 루트 기준 상대 경로**로만 한다.
            # 절대 경로로 판정하면 상위 디렉터리 이름에 걸려 엉뚱하게 전부 제외된다.
            # (실제로 이 프로젝트는 `/Users/goorm/venv/d06` 아래에 있어서, 절대 경로에
            #  'venv' 가 항상 포함돼 모든 파일이 걸러졌다)
            try:
                parts = path.relative_to(target).parts
            except ValueError:
                parts = path.parts
            if any(part in self.excludes for part in parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            yield path

    def scan_file(self, path: Path, data_class: str) -> FileScan:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return FileScan(path=str(path), data_class=data_class, error=str(exc))
        return FileScan(path=str(path), data_class=data_class,
                        findings=self.detector.scan(text))

    def scan_target(self, target, data_class: str) -> List[FileScan]:
        return [self.scan_file(path, data_class) for path in self._iter_files(Path(target))]

    def scan_classes(self, targets: Dict[str, List[Any]]) -> List[FileScan]:
        """{데이터클래스: [경로, ...]} 를 받아 전부 스캔한다."""
        results: List[FileScan] = []
        for data_class, paths in targets.items():
            for target in paths:
                results.extend(self.scan_target(target, data_class))
        return results


def aggregate(scans: List[FileScan]) -> Dict[str, Any]:
    """전체 / 데이터 클래스별 / 규칙별 집계."""
    all_findings = [f for scan in scans for f in scan.findings]

    by_class: Dict[str, Dict[str, int]] = {}
    for scan in scans:
        bucket = by_class.setdefault(scan.data_class, {
            "files": 0, "files_with_findings": 0,
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0,
        })
        bucket["files"] += 1
        if scan.findings:
            bucket["files_with_findings"] += 1
        for finding in scan.findings:
            bucket[finding.severity] = bucket.get(finding.severity, 0) + 1
            bucket["total"] += 1

    by_rule: Dict[str, Dict[str, Any]] = {}
    for finding in all_findings:
        entry = by_rule.setdefault(finding.rule_id, {
            "label": finding.label, "severity": finding.severity, "count": 0,
        })
        entry["count"] += 1

    return {
        "totals": summarize(all_findings),
        "files_scanned": len(scans),
        "by_class": by_class,
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1]["count"])),
    }


def save_json(payload: Dict[str, Any], path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return path
