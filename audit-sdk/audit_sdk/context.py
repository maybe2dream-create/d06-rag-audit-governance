"""요청 단위 감사 컨텍스트.

엔드포인트 시그니처를 바꾸지 않고 request_id / source_ip / actor 를 기록 지점까지
전달한다.

■ dict 를 통째로 갈아끼우지 않고 제자리에서 고치는 이유:
  FastAPI 는 동기 엔드포인트와 의존성을 threadpool 에서 실행하며, 이때 컨텍스트가
  복사된다. 복사본에서 `ContextVar.set()` 을 호출하면 미들웨어가 보는 원본에는
  반영되지 않는다. 반면 dict 객체는 복사본과 원본이 같은 것을 가리키므로 제자리
  수정은 그대로 전달된다.

  이 함정은 SDK 안에 가둬둔다. SDK 를 쓰는 앱이 매번 다시 밟을 일이 아니다.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Dict, Optional

from .event import new_record_id

_context: ContextVar = ContextVar("audit_request_context", default={})


def begin_request(source_ip: str = "", path: str = "", method: str = "") -> Token:
    """요청 시작 시 컨텍스트를 연다. 반환한 토큰은 end_request 에 넘긴다."""
    return _context.set({
        "record_id": new_record_id(),
        "source_ip": source_ip,
        "path": path,
        "method": method,
        "actor": "",
        "role": "",
        "recorded": False,
        "seq": 0,
    })


def end_request(token: Token) -> None:
    _context.reset(token)


def current() -> Dict[str, Any]:
    return _context.get()


def set_actor(actor: str, role: str = "") -> None:
    """인증이 끝난 시점의 사용자를 컨텍스트에 채운다 (제자리 수정)."""
    context = _context.get()
    if not context or not actor:
        return
    context["actor"] = actor
    if role:
        context["role"] = role


def next_sequence() -> int:
    """이 요청에서 몇 번째 감사 이벤트인지 센다. 컨텍스트 밖이면 0."""
    context = _context.get()
    if not context:
        return 0
    context["seq"] = context.get("seq", 0) + 1
    return context["seq"]


def mark_recorded() -> None:
    """이 요청의 감사 이벤트가 이미 기록되었음을 표시한다."""
    context = _context.get()
    if context:
        context["recorded"] = True


def already_recorded() -> bool:
    return bool(_context.get().get("recorded"))


def get(key: str, default: Optional[str] = "") -> Any:
    return _context.get().get(key, default)
