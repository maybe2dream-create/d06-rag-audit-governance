"""Stage 2 인증/인가 의존성."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status

from services.auth_service import auth_service

# d06 Add-on:
# 인증이 끝난 시점의 사용자명을 감사 컨텍스트에 채운다.
from core.audit_setup import audit


# Stage 2 추가:
# Authorization 헤더에서 Bearer 토큰만 분리하는 공통 함수다.
def _extract_bearer_token(authorization: str) -> str:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer 토큰 형식이 올바르지 않습니다.",
        )
    return token.strip()


# Stage 2 추가:
# 현재 요청의 토큰을 검증하고, 로그인 사용자 정보를 반환한다.
def get_current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증이 필요합니다.",
        )

    token = _extract_bearer_token(authorization)
    user = auth_service.verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않거나 만료된 토큰입니다.",
        )
    # d06 Add-on:
    # 여기가 인증의 단일 관문이다. 이 시점에 actor 를 채워두면 이후 rate limit(429)나
    # 권한 거부(403)로 요청이 끊겨도 "누가" 시도했는지가 감사 이벤트에 남는다.
    audit.set_actor(str(user.get("username", "")), str(user.get("role", "")))
    return user


# Stage 2 추가:
# 로그인만 확인하면 되는 엔드포인트에서 사용한다.
def require_login(user: dict = Depends(get_current_user)) -> dict:
    return user


# Stage 2 추가:
# 관리자 role까지 확인해야 하는 엔드포인트에서 사용한다.
def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자 권한이 필요합니다.",
        )
    return user
