"""Stage 2 인증 서비스.

역할:
- 데모 사용자 정보 로딩
- 비밀번호 검증
- 서명된 access token 발급
- token에서 사용자 정보 복원
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Dict, Optional

from core.config import (
    AUTH_TOKEN_EXPIRE_SECONDS,
    DEMO_ADMIN_PASSWORD,
    DEMO_ADMIN_USERNAME,
    DEMO_USER_PASSWORD,
    DEMO_USER_USERNAME,
    INTERNAL_API_SECRET,
    PASSWORD_PEPPER,
)


@dataclass
class UserRecord:
    username: str
    password_hash: str
    role: str


class AuthService:
    """데모용 인증 서비스."""

    def __init__(self) -> None:
        # Stage 2 추가:
        # 아직 DB가 없으므로 `.env` 기반 데모 계정을 메모리에서 구성한다.
        self._users: Dict[str, UserRecord] = {
            DEMO_USER_USERNAME: UserRecord(
                username=DEMO_USER_USERNAME,
                password_hash=self.hash_password(DEMO_USER_PASSWORD),
                role="user",
            ),
            DEMO_ADMIN_USERNAME: UserRecord(
                username=DEMO_ADMIN_USERNAME,
                password_hash=self.hash_password(DEMO_ADMIN_PASSWORD),
                role="admin",
            ),
        }

    @staticmethod
    def hash_password(password: str) -> str:
        # Stage 2 추가:
        # 평문 비밀번호를 직접 비교하지 않고 pepper를 섞은 해시로 비교한다.
        raw = f"{password}:{PASSWORD_PEPPER}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        # Stage 2 추가:
        # 사용자명/비밀번호를 확인하고, 성공 시 최소 사용자 정보만 반환한다.
        user = self._users.get(username.strip())
        if not user:
            return None
        if not hmac.compare_digest(user.password_hash, self.hash_password(password.strip())):
            return None
        return {"username": user.username, "role": user.role}

    def issue_token(self, user: dict) -> str:
        # Stage 2 추가:
        # 로그인 성공 후 사용할 서명된 Bearer 토큰을 생성한다.
        payload = {
            "username": user["username"],
            "role": user["role"],
            "exp": int(time.time()) + AUTH_TOKEN_EXPIRE_SECONDS,
        }
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        encoded_payload = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
        signature = hmac.new(
            INTERNAL_API_SECRET.encode("utf-8"),
            encoded_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{encoded_payload}.{signature}"

    def verify_token(self, token: str) -> Optional[dict]:
        # Stage 2 추가:
        # 토큰 서명, 만료 시간, role 값을 확인한 뒤 사용자 정보를 복원한다.
        try:
            encoded_payload, signature = token.split(".", 1)
        except ValueError:
            return None

        expected_signature = hmac.new(
            INTERNAL_API_SECRET.encode("utf-8"),
            encoded_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None

        try:
            padding = "=" * (-len(encoded_payload) % 4)
            raw = base64.urlsafe_b64decode((encoded_payload + padding).encode("ascii")).decode("utf-8")
            payload = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            return None

        if payload.get("exp", 0) < int(time.time()):
            return None

        username = payload.get("username", "")
        role = payload.get("role", "")
        if username not in self._users or role not in {"user", "admin"}:
            return None
        return {"username": username, "role": role}

# Stage 2 추가:
# `app.py`에서는 이 공통 인스턴스를 import 해서 사용한다.
auth_service = AuthService()
