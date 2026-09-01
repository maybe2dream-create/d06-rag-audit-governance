"""d06 미션: 개인정보 통제 부트스트랩.

이 앱의 `PIIGuard` 인스턴스를 하나 만들어 전역으로 공유한다.
탐지되면 감사 이벤트(`pii_detected`)를 남긴다 — 무엇이 언제 어느 데이터 클래스에서
탐지되어 어떻게 통제되었는지가 그 자체로 감사 대상이다.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
D06_DIR = BASE_DIR.parent

# 미설치 상태에서도 동작하도록 형제 폴더의 SDK 를 경로에 얹는다.
_GUARD_DIR = D06_DIR / "pii-guard"
if _GUARD_DIR.is_dir() and str(_GUARD_DIR) not in sys.path:
    sys.path.insert(0, str(_GUARD_DIR))

from pii_guard import (  # noqa: E402
    FEEDBACK_LOG, INFERENCE_LOG, TRAINING_DATA, GuardResult, PIIGuard,
)

from core.audit_setup import audit  # noqa: E402

POLICY_PATH = D06_DIR / "configs" / "pii_policy.json"


def _on_detect(result: GuardResult) -> None:
    """탐지 시 감사 이벤트를 남긴다.

    purpose 에는 **마스킹된 요약만** 넣는다. 어떤 값이 탐지됐는지를 원문으로 남기면
    개인정보를 지우려고 만든 기록이 개인정보를 다시 퍼뜨리게 된다.
    """
    summary = result.summary()
    detail = ", ".join(
        "{}×{}".format(rule_id, count)
        for rule_id, count in sorted(_count_rules(result).items())
    )
    audit.record(
        action="pii_detected",
        asset="data_class:{}".format(result.data_class),
        result="blocked" if result.blocked else "controlled",
        purpose="탐지 {}건 (CRITICAL {}, HIGH {}, MEDIUM {}, LOW {}) — {}".format(
            summary["total"], summary["CRITICAL"], summary["HIGH"],
            summary["MEDIUM"], summary["LOW"], detail or "-"),
    )


def _count_rules(result: GuardResult):
    counts = {}
    for finding in result.findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    return counts


guard = PIIGuard.from_config(POLICY_PATH, on_detect=_on_detect)

# 로그 마스킹 전용 인스턴스 — 감사 이벤트를 남기지 않는다.
#
# 로그는 한 요청에서 여러 줄이 찍힌다. 줄마다 pii_detected 를 남기면 감사 로그가
# 마스킹 기록으로 뒤덮이고, 더 나쁘게는 audit.record 가 "이 요청은 이미 기록됨"
# 표시를 남겨 미들웨어의 거부 이벤트(access_denied 등)를 삼켜버린다.
# 통제는 하되 기록은 하지 않는 경로가 따로 필요하다.
log_guard = PIIGuard.from_config(POLICY_PATH)

__all__ = ["guard", "log_guard", "TRAINING_DATA", "INFERENCE_LOG", "FEEDBACK_LOG"]
