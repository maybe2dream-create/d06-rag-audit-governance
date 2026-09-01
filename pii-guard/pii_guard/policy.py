"""데이터 클래스별 통제 정책.

하드코딩하지 않고 외부 Config(`configs/pii_policy.json`)로 통제한다.
같은 주민등록번호라도 학습 데이터에서는 마스킹, 피드백 로그에서는 가명처리처럼
데이터의 쓰임에 따라 조치가 달라져야 하기 때문이다.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .patterns import CRITICAL, HIGH, LOW, MEDIUM
from .redactor import ALLOW, BLOCK, MASK, PSEUDONYMIZE

TRAINING_DATA = "training_data"
INFERENCE_LOG = "inference_log"
FEEDBACK_LOG = "feedback_log"
AUDIT_EVENT = "audit_event"

DATA_CLASSES = (TRAINING_DATA, INFERENCE_LOG, FEEDBACK_LOG, AUDIT_EVENT)

DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": True,
    "classes": {
        # 학습 데이터: 차단이 아니라 마스킹이 기본이다. 차단하면 문서가 통째로
        # 검색에서 사라져 RAG 가 무력해진다. PII 만 가리고 문서는 쓴다.
        TRAINING_DATA: {CRITICAL: MASK, HIGH: MASK, MEDIUM: MASK, LOW: ALLOW},
        # 추론 로그: 평문 파일이라 암호화도 파기도 되지 않는다. 남기지 않는 게 원칙.
        INFERENCE_LOG: {CRITICAL: MASK, HIGH: MASK, MEDIUM: PSEUDONYMIZE, LOW: ALLOW},
        # 피드백 로그: 자유입력이라 무엇이 들어올지 모른다. 가명처리로 통계는 살린다.
        FEEDBACK_LOG: {CRITICAL: MASK, HIGH: MASK, MEDIUM: PSEUDONYMIZE, LOW: ALLOW},
        # 감사 이벤트는 암호화·파기로 통제된다. 여기서 마스킹하면 파기 검증이 불가능해진다.
        AUDIT_EVENT: {CRITICAL: ALLOW, HIGH: ALLOW, MEDIUM: ALLOW, LOW: ALLOW},
    },
}


class PIIPolicy:
    """데이터 클래스 × 심각도 → 조치."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or DEFAULT_POLICY
        self.enabled = bool(self.config.get("enabled", True))
        self.classes = self.config.get("classes", DEFAULT_POLICY["classes"])
        # 스캔에서 "CRITICAL 0건이어야 한다"고 강제할 클래스
        self.enforced_classes = self.config.get(
            "enforced_classes", [INFERENCE_LOG, FEEDBACK_LOG])

    @classmethod
    def load(cls, path) -> "PIIPolicy":
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        # `_` 로 시작하는 키는 설명용 주석이므로 걷어낸다.
        classes = {
            name: {k: v for k, v in table.items() if not k.startswith("_")}
            for name, table in raw.get("classes", {}).items()
            if not name.startswith("_")
        }
        return cls({"enabled": raw.get("enabled", True), "classes": classes,
                    "enforced_classes": raw.get("enforced_classes", [])})

    def action_for(self, data_class: str, severity: str) -> str:
        if not self.enabled:
            return ALLOW
        table = self.classes.get(data_class, {})
        return table.get(severity, MASK)

    def actions_for(self, data_class: str, findings) -> Dict[str, str]:
        """탐지된 규칙별 조치를 정한다."""
        return {f.rule_id: self.action_for(data_class, f.severity) for f in findings}

    def blocks(self, data_class: str, findings) -> bool:
        """이 데이터 자체를 거부해야 하는지."""
        if not self.enabled:
            return False
        return any(self.action_for(data_class, f.severity) == BLOCK for f in findings)
