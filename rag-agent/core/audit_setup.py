"""d06 Add-on: 감사 SDK 부트스트랩.

두 가지를 만든다.

  audit       — 요청/엔드포인트 단위 감사 클라이언트 (FastAPI 계층에서 사용)
  audit_turn  — 턴 단위 감사 기록기 (RAG/Agent 계층에서 사용, 기록 시점 해시체인)

SDK 를 정식 설치(`pip install -e ../audit-sdk`)했다면 그대로 import 되고,
설치하지 않았다면 아래 경로 부트스트랩이 형제 폴더에서 찾는다.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
D06_DIR = BASE_DIR.parent

for _sibling in ("audit-sdk", "pii-guard"):
    _path = D06_DIR / _sibling
    if _path.is_dir() and str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from audit_sdk import AuditClient  # noqa: E402
from audit_sdk.turn import AuditTurnRecorder  # noqa: E402
from pii_guard import PIIGuard  # noqa: E402

# 서비스 이름은 감사 이벤트의 department 필드가 된다.
audit = AuditClient(service="rag-service", out_dir=BASE_DIR / "audit_out",
                    filename="rag_audit_events.jsonl")

# 턴 기록기가 쓰는 마스킹기.
#
# core.pii_setup 이 아니라 pii_guard 를 직접 쓴다. core.pii_setup 은 탐지 시 audit.record 를
# 호출하므로 여기서 가져오면 import 순환이 생기고, 감사 기록 안에서 또 감사 기록이
# 일어나 재진입 문제가 된다.
_mask_guard = PIIGuard.from_config(D06_DIR / "configs" / "pii_policy.json")

audit_turn = AuditTurnRecorder(
    sink_dir=D06_DIR / "audit-events",
    access_policy_path=D06_DIR / "configs" / "lab10_access_control_policy.json",
    pii_guard=_mask_guard,
)

__all__ = ["audit", "audit_turn"]
