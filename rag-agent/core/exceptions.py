"""Stage 6 공통 보안 예외 처리 모듈.

역할:
- HTTPException 공통 처리
- 입력값 검증 실패(RequestValidationError) 공통 처리
- 일반 Exception 공통 처리
- 사용자에게는 안전한 메시지를, 서버 로그에는 원인 정보를 남긴다.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from core.logger import log_app_event, log_security_event


def _security_event_name(exc: HTTPException) -> str:
    """Stage 6 정리:
    상태코드별로 보안 로그 이름을 더 구체적으로 나눈다.
    """
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return "authentication exception"
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        return "authorization exception"
    if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
        return "validation exception"
    if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
        return "rate limit exception"
    return "http security exception"


def register_exception_handlers(app: FastAPI) -> None:
    """FastAPI 앱에 공통 예외 처리기를 등록한다."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        payload = {
            "path": request.url.path,
            "status_code": exc.status_code,
            "detail": exc.detail,
        }
        if exc.status_code in (
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_429_TOO_MANY_REQUESTS,
        ):
            # Stage 6 정리:
            # 401/403/422/429를 같은 이름으로 묶지 않고 의미별로 구분해서 기록한다.
            log_security_event(_security_event_name(exc), payload)
        else:
            log_app_event("http exception", payload)

        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        log_security_event(
            "request validation failed",
            {
                "path": request.url.path,
                "errors": exc.errors(),
            },
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "입력값 검증에 실패했습니다."},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        log_security_event(
            "unhandled server exception",
            {
                "path": request.url.path,
                "error_type": exc.__class__.__name__,
                "message": str(exc),
            },
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "서버 내부 오류가 발생했습니다."},
        )
