"""Stage 4 로그 마스킹 공통 모듈.

역할:
- 민감 키를 식별한다.
- 로그 직전에 민감 값을 마스킹한다.

■ d06 미션 확장 — 키 기반 + 값 기반 두 겹:
  기존 방식은 **키 이름**(password, token …)만 보고 마스킹했다. 그래서
  `{"question": "김테스트 900101-1234568 알려줘"}` 처럼 키가 목록에 없으면
  값 안에 무엇이 들었든 그대로 통과했다. 실제로 app.log 에 질문 원문이 남아 있었다.
  이제 키 기반을 통과한 값에 대해 pii_guard 탐지를 한 번 더 돌린다.
  (기존 SENSITIVE_KEYS 동작은 그대로 두어 회귀가 없다)
"""

from __future__ import annotations

from typing import Any, Dict

from core.pii_setup import INFERENCE_LOG, log_guard


SENSITIVE_KEYS = {
    "password",
    "token",
    "secret",
    "authorization",
    "cookie",
    "session",
    "password_hash",
    "access_token",
}


def mask_text(value: str) -> str:
    if not value:
        return value
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def mask_pii(value: str) -> str:
    """값 안에 담긴 개인정보를 정책(inference_log)대로 통제한다."""
    try:
        return log_guard.process(value, data_class=INFERENCE_LOG).text
    except Exception:  # noqa: BLE001 - 마스킹 실패가 로깅을 막아서는 안 된다
        return value


def mask_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return mask_mapping(value)
    if isinstance(value, list):
        return [mask_value(key, item) for item in value]
    if key.lower() in SENSITIVE_KEYS and isinstance(value, str):
        return mask_text(value)
    # d06 미션 추가:
    # 키 기반을 통과한 문자열도 값 안을 들여다본다.
    if isinstance(value, str):
        return mask_pii(value)
    return value


def mask_mapping(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {key: mask_value(key, value) for key, value in payload.items()}

