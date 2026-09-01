"""5W1H 감사 이벤트 계약.

이 모듈이 감사 로그 포맷의 **단일 정의처**다. 앱마다 필드를 손으로 맞추면
서비스가 늘어날수록 포맷이 갈라지고, 결국 한 파이프라인으로 처리할 수 없게 된다.

■ 감사엔진을 import 하지 않는다:
  필드 이름만 맞추고 엔진 코드는 쓰지 않는다. 감사 대상이 감사 도구의 코드를
  재사용하면 같은 버그를 공유해 결함을 놓친다.
  (엔진 쪽 정의: audit-engine/audit_engine/models.py 의 AuditEvent)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# 감사엔진 AuditEvent 와 이름·순서를 맞춘 10개 필드.
AUDIT_FIELDS = (
    "timestamp",    # When   UTC
    "actor",        # Who    사용자 식별자
    "role",         # Who    권한
    "department",   # Who    소속 (SDK 에서는 service 이름)
    "action",       # How    수행 행위
    "asset",        # What   대상 자산
    "record_id",    # What   요청 식별자
    "source_ip",    # Where  접속 IP
    "purpose",      # Why    작업 사유 (질문 원문 등 PII 가 들어갈 수 있다)
    "result",       # Result
)

# 행위자를 특정할 수 없을 때 쓰는 값.
# 빈 문자열로 두면 '행위자 누락'과 '익명 접근'을 구분할 수 없어 추적성 판정이 흐려진다.
ANONYMOUS_ACTOR = "UNKNOWN_ANONYMOUS"
UNKNOWN_ROLE = "unknown"
UNKNOWN_IP = "unknown"
UNSPECIFIED_PURPOSE = "unspecified"


def new_record_id() -> str:
    """요청 단위 추적 식별자."""
    return "req-" + uuid.uuid4().hex[:8]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event(
    action: str,
    asset: str,
    result: str,
    service: str,
    actor: str = "",
    role: str = "",
    purpose: str = "",
    record_id: str = "",
    source_ip: str = "",
    timestamp: str = "",
) -> Dict[str, Any]:
    """5W1H 감사 이벤트 dict 를 만든다. 빈 값은 명시적 기본값으로 채운다."""
    return {
        "timestamp": timestamp or utc_now(),
        "actor": actor or ANONYMOUS_ACTOR,
        "role": role or UNKNOWN_ROLE,
        "department": service,
        "action": action,
        "asset": asset,
        "record_id": record_id or new_record_id(),
        "source_ip": source_ip or UNKNOWN_IP,
        "purpose": purpose or UNSPECIFIED_PURPOSE,
        "result": result,
    }


def normalize(event: Dict[str, Any]) -> Dict[str, Any]:
    """정의된 10개 필드만, 정의된 순서로 남긴다."""
    return {field: event.get(field, "") for field in AUDIT_FIELDS}


def actor_from_user(user: Optional[Dict[str, Any]]) -> "tuple":
    """로그인 사용자 dict 에서 (actor, role) 을 꺼낸다."""
    if not user:
        return "", ""
    return str(user.get("username", "")), str(user.get("role", ""))
