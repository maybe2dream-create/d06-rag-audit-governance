"""텍스트에서 개인정보·민감정보를 탐지한다."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .patterns import RULES, SEVERITY_ORDER, Rule


@dataclass
class Finding:
    """탐지 결과 한 건.

    `raw` 는 원본 값이라 **리포트에 그대로 실으면 안 된다.** 통제(마스킹) 단계에서만
    쓰고, 밖으로 나가는 `to_dict()` 는 마스킹된 `preview` 만 담는다.
    탐지 리포트 자체가 또 하나의 유출 경로가 되지 않게 하기 위해서다.
    """

    rule_id: str
    label: str
    severity: str
    start: int
    end: int
    raw: str = field(repr=False)
    preview: str = ""
    validated: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "label": self.label,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "preview": self.preview,
            "validated": self.validated,
        }


class PIIDetector:
    """규칙 + 검증기 기반 탐지기."""

    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules = list(rules if rules is not None else RULES)

    def scan(self, text: str) -> List[Finding]:
        if not text:
            return []

        findings: List[Finding] = []
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                value = match.group(0)
                validated = None
                severity = rule.severity

                if rule.validator is not None:
                    validated = bool(rule.validator(value))
                    if not validated:
                        # 검증 실패 = 형식만 닮은 값. 버리거나 등급을 낮춘다.
                        if rule.demoted_severity is None:
                            continue
                        severity = rule.demoted_severity

                findings.append(Finding(
                    rule_id=rule.rule_id,
                    label=rule.label,
                    severity=severity,
                    start=match.start(),
                    end=match.end(),
                    raw=value,
                    preview=rule.mask(value),
                    validated=validated,
                ))

        return self._resolve_overlaps(findings)

    @staticmethod
    def _resolve_overlaps(findings: List[Finding]) -> List[Finding]:
        """겹친 탐지는 하나만 남긴다.

        주민등록번호 `900101-1234567` 은 계좌번호 패턴에도 걸린다. 둘 다 남기면
        같은 문자열이 두 번 집계되어 건수가 부풀고, 마스킹도 두 번 적용된다.
        심각도가 높은 쪽, 같으면 더 긴 매치를 남긴다.
        """
        ordered = sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -(f.end - f.start), f.start),
        )
        kept: List[Finding] = []
        for finding in ordered:
            if any(finding.start < k.end and k.start < finding.end for k in kept):
                continue
            kept.append(finding)
        return sorted(kept, key=lambda f: f.start)


def summarize(findings: List[Finding]) -> Dict[str, int]:
    """등급별 건수 요약."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": len(findings)}
    for finding in findings:
        if finding.severity in summary:
            summary[finding.severity] += 1
    return summary
