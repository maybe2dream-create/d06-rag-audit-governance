"""pii_guard — 개인정보·민감정보 탐지 및 통제.

서비스 학습 데이터 / 추론 로그 / 사용자 피드백 로그에 섞여 들어오는 개인정보를
탐지하고, 데이터 클래스별 정책에 따라 마스킹·가명처리·차단한다.

    from pii_guard import PIIGuard
    guard = PIIGuard.from_config("configs/pii_policy.json")

    result = guard.process(text, data_class="training_data")
    result.text       # 통제가 적용된 본문
    result.findings   # 탐지 결과 (원본 값은 리포트에 나가지 않는다)
    result.blocked    # 정책상 데이터 자체를 거부해야 하는가

■ 의존성 없음:
  표준 라이브러리만 쓴다. 감사 기록이 필요하면 `on_detect` 콜백을 넘긴다 —
  audit_sdk 에 하드 의존하지 않기 위해서다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .detector import Finding, PIIDetector, summarize
from .patterns import CRITICAL, HIGH, LOW, MEDIUM, RULES, Rule
from .policy import (
    AUDIT_EVENT, DATA_CLASSES, FEEDBACK_LOG, INFERENCE_LOG,
    TRAINING_DATA, PIIPolicy,
)
from .redactor import ALLOW, BLOCK, DROP, MASK, PSEUDONYMIZE, TOKEN, Redactor

__all__ = [
    "PIIGuard", "GuardResult", "PIIDetector", "PIIPolicy", "Redactor", "Finding",
    "summarize", "RULES", "Rule",
    "CRITICAL", "HIGH", "MEDIUM", "LOW",
    "ALLOW", "MASK", "PSEUDONYMIZE", "DROP", "BLOCK", "TOKEN",
    "TRAINING_DATA", "INFERENCE_LOG", "FEEDBACK_LOG", "AUDIT_EVENT", "DATA_CLASSES",
]

__version__ = "1.0.0"


@dataclass
class GuardResult:
    """통제 적용 결과."""

    text: str
    findings: List[Finding] = field(default_factory=list)
    applied: List[Dict[str, str]] = field(default_factory=list)
    blocked: bool = False
    data_class: str = ""

    @property
    def changed(self) -> bool:
        return bool(self.applied)

    def summary(self) -> Dict[str, int]:
        return summarize(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_class": self.data_class,
            "blocked": self.blocked,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "applied": self.applied,
        }


class PIIGuard:
    """탐지 + 정책 + 통제를 묶은 진입점."""

    def __init__(self, policy: Optional[PIIPolicy] = None,
                 detector: Optional[PIIDetector] = None,
                 redactor: Optional[Redactor] = None,
                 on_detect: Optional[Callable[[GuardResult], None]] = None):
        self.policy = policy or PIIPolicy()
        self.detector = detector or PIIDetector()
        self.redactor = redactor or Redactor()
        # 탐지되면 호출된다. 감사 이벤트를 남기고 싶을 때 쓴다.
        self.on_detect = on_detect

    @classmethod
    def from_config(cls, path, **kwargs) -> "PIIGuard":
        return cls(policy=PIIPolicy.load(path), **kwargs)

    def scan(self, text: str) -> List[Finding]:
        return self.detector.scan(text)

    def tokenize(self, text: str) -> str:
        """탐지된 개인정보를 전부 토큰으로 치환한다.

        감사 이벤트 기록 시점에 쓴다. 부분 마스킹(010-****-5678)은 자릿수와 일부 값이
        남아 다른 정보와 조합하면 복원될 수 있다. 감사 로그는 장기 보관되므로 조합
        공격에 노출되는 시간이 길다 — 여기서는 형식조차 남기지 않는다.
        """
        if not text:
            return text
        findings = self.detector.scan(text)
        if not findings:
            return text
        actions = {f.rule_id: TOKEN for f in findings}
        redacted, _applied = self.redactor.apply(text, findings, actions)
        return redacted

    def process(self, text: str, data_class: str = TRAINING_DATA) -> GuardResult:
        """탐지 → 정책 조회 → 통제 적용."""
        if not text or not self.policy.enabled:
            return GuardResult(text=text, data_class=data_class)

        findings = self.detector.scan(text)
        if not findings:
            return GuardResult(text=text, data_class=data_class)

        blocked = self.policy.blocks(data_class, findings)
        actions = self.policy.actions_for(data_class, findings)
        redacted, applied = self.redactor.apply(text, findings, actions)

        result = GuardResult(text=redacted, findings=findings, applied=applied,
                             blocked=blocked, data_class=data_class)
        if self.on_detect:
            self.on_detect(result)
        return result
