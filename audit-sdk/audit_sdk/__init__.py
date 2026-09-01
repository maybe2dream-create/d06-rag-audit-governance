"""audit_sdk — 5W1H 감사 기록 SDK.

앱은 이 패키지를 쓰기만 하면 된다. 감사 로그의 필드 계약, append-only 적재,
요청 컨텍스트, 거부 요청 자동 기록이 모두 안에 들어 있다.

    from audit_sdk import AuditClient
    from audit_sdk.integrations.fastapi import install_audit

    audit = AuditClient(service="rag-service", out_dir=BASE_DIR / "audit_out")
    install_audit(app, audit)

    audit.record(action="rag_query", asset="vector_index",
                 result="success", user=current_user, purpose=question)

■ 코어는 감사엔진에 의존하지 않는다:
  엔진을 부르는 것은 `audit_sdk.pipeline` 뿐이고, 그건 배치 실행 쪽에서만 import 한다.
  감사 대상(앱)이 감사 도구(엔진)의 코드를 재사용하면 같은 버그를 공유해 결함을 놓친다.
"""

from __future__ import annotations

from .client import AuditClient
from .event import (
    ANONYMOUS_ACTOR,
    AUDIT_FIELDS,
    build_event,
    new_record_id,
    normalize,
    utc_now,
)
from .sink import AuditSink, JsonlSink, MemorySink

__all__ = [
    "AuditClient",
    "AuditSink",
    "JsonlSink",
    "MemorySink",
    "AUDIT_FIELDS",
    "ANONYMOUS_ACTOR",
    "build_event",
    "normalize",
    "new_record_id",
    "utc_now",
]

__version__ = "1.0.0"
