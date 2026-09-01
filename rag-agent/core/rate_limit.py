"""Stage 3 rate limit 공통 모듈.

역할:
- 메모리 기반 요청 횟수 추적
- 경로별 / 사용자별 제한 검사
- 초과 시 429 예외 반환
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import DefaultDict, List, Optional

from fastapi import HTTPException, Request, status


class InMemoryRateLimiter:
    """가벼운 학습용 메모리 기반 rate limiter."""

    def __init__(self) -> None:
        self._events: DefaultDict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: str, max_requests: int, window_seconds: int) -> None:
        now = time.time()
        with self._lock:
            recent = [ts for ts in self._events[key] if now - ts < window_seconds]
            if len(recent) >= max_requests:
                self._events[key] = recent
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.",
                )
            recent.append(now)
            self._events[key] = recent


rate_limiter = InMemoryRateLimiter()


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def enforce_rate_limit(
    request: Request,
    scope: str,
    max_requests: int,
    window_seconds: int,
    identity: Optional[str] = None,
) -> None:
    """scope와 사용자/IP를 합쳐 제한 키를 만든다."""
    key = f"{scope}:{identity or _client_ip(request)}"
    rate_limiter.check(key, max_requests=max_requests, window_seconds=window_seconds)
