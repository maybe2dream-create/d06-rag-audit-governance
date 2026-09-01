"""FastAPI 연동 — 한 줄로 감사 기록을 붙인다.

    from audit_sdk.integrations.fastapi import install_audit
    install_audit(app, audit)

■ 미들웨어가 필요한 이유:
  `require_login` / `require_admin` 같은 의존성이 거부한 요청은 엔드포인트 함수
  본문에 들어오지 않는다. 핸들러에서만 기록하면 **권한 없는 접근 시도가 감사 로그에
  통째로 빠진다.** 감사 관점에서 가장 봐야 할 이벤트가 사라지는 셈이다.

  성공 요청은 핸들러가 도메인 정보(질문 내용, 도구 이름)를 붙여 직접 기록하므로
  여기서는 2xx 를 건드리지 않는다. 요청당 감사 이벤트는 한 건이다.
"""

from __future__ import annotations

from typing import Any

from .. import context
from ..client import AuditClient

# 응답 상태코드 → (action, result, purpose).
# 2xx 는 핸들러가 직접 기록하므로 여기 없다.
STATUS_ACTION_MAP = {
    401: ("access_denied", "denied", "unauthenticated-attempt"),
    403: ("access_denied", "denied", "unauthorized-attempt"),
    422: ("input_validation_failed", "failure", "malformed-request"),
    429: ("rate_limit_block", "denied", "throttle"),
}


def client_ip(request: Any) -> str:
    if getattr(request, "client", None) and request.client.host:
        return request.client.host
    return "unknown"


def install_audit(app: Any, audit: AuditClient) -> None:
    """FastAPI 앱에 감사 컨텍스트 미들웨어를 등록한다."""

    @app.middleware("http")
    async def audit_context_middleware(request, call_next):
        token = context.begin_request(
            source_ip=client_ip(request),
            path=request.url.path,
            method=request.method,
        )
        try:
            try:
                response = await call_next(request)
            except Exception as exc:  # noqa: BLE001 - 기록 후 그대로 다시 던진다
                # 처리되지 않은 예외는 ServerErrorMiddleware(가장 바깥)가 500 으로
                # 바꾸므로, 이 미들웨어에는 응답이 아니라 예외로 올라온다.
                _record_status(audit, request, 500, exc.__class__.__name__)
                raise

            if response.status_code >= 400:
                _record_status(audit, request, response.status_code)
            return response
        finally:
            context.end_request(token)


def _record_status(audit: AuditClient, request: Any, status_code: int,
                   error_type: str = "") -> None:
    """거부·오류 응답을 감사 이벤트로 남긴다."""
    # 핸들러가 이미 이 요청을 기록했다면 남기지 않는다.
    # 예: 로그인 실패는 핸들러가 auth_login_failed(시도한 사용자명 포함)를 남기고
    # 401 로 끝난다. 여기서 access_denied 를 또 남기면 같은 record_id 가 두 번
    # 등장해 추적성이 훼손된다.
    if context.already_recorded():
        return

    if status_code in STATUS_ACTION_MAP:
        action, result, purpose = STATUS_ACTION_MAP[status_code]
    elif status_code >= 500:
        action, result = "app_error", "failure"
        purpose = error_type or "server-error"
    else:
        action, result, purpose = "http_error", "failure", "status-{}".format(status_code)

    audit.record(
        action=action,
        # 어떤 경로를 노렸는지가 곧 감사 대상 자산이다.
        asset="endpoint:{}".format(context.get("path") or request.url.path),
        result=result,
        purpose=purpose,
    )
