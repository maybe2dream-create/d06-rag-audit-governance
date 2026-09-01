"""Stage 1 secret 관리용 공통 설정 파일.

목표:
- 소스코드에 secret 문자열을 직접 쓰지 않는다.
- `.env` 또는 OS 환경변수에서 값을 읽는다.
- `app.py`는 이 파일을 import 해서 설정을 사용한다.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict


BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
LEGACY_DOCUMENTS_PATH = BASE_DIR / "documents.json"
FALLBACK_DOCUMENTS_PATH = BASE_DIR / "document.json"
LOG_DIR = BASE_DIR / "logs"


def _load_dotenv(path: Path) -> Dict[str, str]:
    """간단한 `.env` 파서.

    외부 패키지 의존성을 늘리지 않기 위해 Stage 1에서는
    `python-dotenv` 없이 직접 key=value 형식만 읽는다.
    """
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


# Stage 1 추가:
# `.env` 파일을 미리 읽어 두고, 이후 `get_env()`가 환경변수와 함께 참조한다.
_DOTENV = _load_dotenv(ENV_PATH)


def get_env(name: str, default: str = "") -> str:
    """환경변수 우선, 없으면 `.env`, 둘 다 없으면 기본값 사용."""
    return os.getenv(name, _DOTENV.get(name, default))


# Stage 1 추가:
# 애플리케이션 전반에서 재사용할 공통 설정값과 secret 값들이다.
APP_ENV = get_env("APP_ENV", "development")

# d06 Add-on:
# 문서 집합을 환경변수로 바꿀 수 있게 한다. 테스트용 더미 문서(PII 포함)를 투입할 때
# 실제 documents.json 을 덮어쓰지 않고 경로만 바꿔 끼우기 위해서다.
_DOCUMENTS_ENV = get_env("DOCUMENTS_PATH", "").strip()
if _DOCUMENTS_ENV:
    _candidate = Path(_DOCUMENTS_ENV)
    DOCUMENTS_PATH = _candidate if _candidate.is_absolute() else (BASE_DIR / _candidate)
elif LEGACY_DOCUMENTS_PATH.exists():
    DOCUMENTS_PATH = LEGACY_DOCUMENTS_PATH
else:
    DOCUMENTS_PATH = FALLBACK_DOCUMENTS_PATH

# d06 Add-on:
# RAG 임베딩/생성 제공자. 기본은 실제 Gemini 호출이다.
#   gemini = 실제 API 호출 (운영/정상 경로)
#   local  = 결정적 로컬 스텁 — API 키·네트워크 없이 감사 로그 경로를 수동 테스트할 때만.
#            테스트 제공자가 답을 만들었다는 사실 자체를 감사 이벤트로 남긴다.
RAG_PROVIDER = get_env("RAG_PROVIDER", "gemini").strip().lower()

# Gemini 관련 설정은 이제 `app.py`가 직접 읽지 않고 이 파일을 통해 사용한다.
GEMINI_API_KEY = get_env("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = get_env("GEMINI_MODEL", "gemini-2.5-flash").strip()
GEMINI_EMBED_MODEL = get_env(
    "GEMINI_EMBED_MODEL",
    "models/gemini-embedding-001",
).strip()

# Stage 1에서 미리 분리해 두는 내부용 secret 값.
# 이후 인증/인가, 관리자 기능, 내부 API 보호 단계에서 재사용할 수 있다.
INTERNAL_API_SECRET = get_env("INTERNAL_API_SECRET", "change-me-in-env").strip()
PASSWORD_PEPPER = get_env("PASSWORD_PEPPER", "change-me-in-env").strip()

# Stage 1 추가:
# FastAPI 앱 메타 정보도 설정 파일에서 읽어 `app.py` 수정량을 줄인다.
APP_TITLE = get_env("APP_TITLE", "RAG Agent Minimal API").strip()
APP_DESCRIPTION = get_env(
    "APP_DESCRIPTION",
    "문서/임베딩/LLM/RAG/Agent/API를 한 파일에 담은 최소 학습용 서비스",
).strip()
APP_VERSION = get_env("APP_VERSION", "0.1.0").strip()

# Stage 2 추가:
# DB가 아직 없으므로 `.env`에서 읽은 데모 계정으로 인증/인가를 검증한다.
DEMO_USER_USERNAME = get_env("DEMO_USER_USERNAME", "user").strip()
DEMO_USER_PASSWORD = get_env("DEMO_USER_PASSWORD", "user1234").strip()
DEMO_ADMIN_USERNAME = get_env("DEMO_ADMIN_USERNAME", "admin").strip()
DEMO_ADMIN_PASSWORD = get_env("DEMO_ADMIN_PASSWORD", "admin1234").strip()
AUTH_TOKEN_EXPIRE_SECONDS = int(get_env("AUTH_TOKEN_EXPIRE_SECONDS", "3600"))

# Stage 3 추가:
# 민감 엔드포인트에 적용할 요청 제한 기준값이다. env 또는 OS 환경변수에서 읽어 재사용한다.
RATE_LIMIT_WINDOW_SECONDS = int(get_env("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_LOGIN_MAX = int(get_env("RATE_LIMIT_LOGIN_MAX", "5"))
RATE_LIMIT_ADMIN_MAX = int(get_env("RATE_LIMIT_ADMIN_MAX", "10"))
RATE_LIMIT_RAG_MAX = int(get_env("RATE_LIMIT_RAG_MAX", "20"))
