"""rag-agent/5-api.py — FastAPI 진입점.

사용자 컨텍스트(actor / role / department / request_id)를 만들어 감사 계층에 넘긴다.
RAG·Agent 로직은 3-2-rag.py / 4-agent.py 가 갖고 있고 여기서는 호출만 한다.

실행:
  RAG_PROVIDER=local python3 -m uvicorn 5-api:app --port 8000   # 파일명이 숫자로 시작해
                                                                 # importlib 로 로드된다
  python3 5-api.py                                              # 직접 실행 (권장)
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def _load_sibling(module_name: str, filename: str):
    """숫자로 시작하는 파일명은 일반 import 가 안 되므로 경로로 직접 로드한다."""
    spec = importlib.util.spec_from_file_location(module_name, BASE_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


RAG = _load_sibling("rag_core", "3-2-rag.py")
AGENT = _load_sibling("agent_core", "4-agent.py")

load_documents = RAG.load_documents
run_rag = RAG.run_rag
run_agent_with_trace = AGENT.run_agent_with_trace
CHAT_MODEL = RAG.CHAT_MODEL
EMBED_MODEL = RAG.EMBED_MODEL

from core.config import (  # noqa: E402
    APP_DESCRIPTION, APP_TITLE, APP_VERSION, DOCUMENTS_PATH,
    RATE_LIMIT_ADMIN_MAX, RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_RAG_MAX,
    RATE_LIMIT_WINDOW_SECONDS,
)
from core.exceptions import register_exception_handlers  # noqa: E402
from core.logger import log_app_event, log_security_event  # noqa: E402
from core.audit_setup import audit, audit_turn  # noqa: E402
from audit_sdk.integrations.fastapi import install_audit  # noqa: E402
from core.pii_setup import FEEDBACK_LOG, TRAINING_DATA, guard  # noqa: E402
from core.rate_limit import enforce_rate_limit  # noqa: E402
from core.security import require_admin, require_login  # noqa: E402
from schemas.request_schemas import (  # noqa: E402
    FeedbackRequest, LoginRequest, QuestionRequest, RagRequest,
)
from services.auth_service import auth_service  # noqa: E402

# =============================================================================
# 6. API
# =============================================================================
# Stage 1 추가:
# 앱 메타 정보(title/description/version)도 설정 파일에서 읽도록 바뀌었다.
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
)

# Stage 6 추가:
# 공통 보안 예외 처리기를 앱 시작 시 등록한다.
register_exception_handlers(app)

# d06 Add-on:
# 감사 SDK 연동 한 줄. 요청 컨텍스트(request_id/IP)를 세우고, 핸들러에 도달하지
# 못한 요청(401/403/422/429/5xx)을 감사 이벤트로 남긴다.
install_audit(app, audit)


# Stage 4 추가:
# 모든 HTTP 요청의 기본 정보를 일반 앱 로그(app.log)에 남긴다.
# 여기서는 method, path, status_code, client_ip 를 기록한다.
@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    response = await call_next(request)
    log_app_event(
        "http request",
        {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "client_ip": request.client.host if request.client else "unknown",
        },
    )
    return response


def translate_error(exc: BaseException) -> HTTPException:
    # Stage 4 추가:
    # 예외가 사용자 응답으로 변환되기 전에 보안 로그(security.log)에 남긴다.
    if isinstance(exc, SystemExit):
        log_security_event("system exit translated", {"error_type": exc.__class__.__name__})
        return HTTPException(
            status_code=500,
            detail="Gemini 설정 또는 실행 중 종료가 발생했습니다.",
        )
    log_security_event(
        "unhandled application error translated",
        {"error_type": exc.__class__.__name__, "detail": str(exc)},
    )
    # Stage 6 추가:
    # 내부 예외 상세 메시지는 사용자에게 그대로 주지 않고 공통 메시지로 응답한다.
    return HTTPException(status_code=500, detail="서버 내부 오류가 발생했습니다.")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Stage 2 추가:
# 로그인 엔드포인트를 분리하고, 성공 시 Bearer 토큰을 발급한다.
# Stage 3 추가:
# 로그인은 무차별 대입 시도가 잦을 수 있어 사용자명 기준 + IP fallback 으로 제한한다.
@app.post("/auth/login")
def login(request: LoginRequest, http_request: Request) -> dict[str, object]:
    """Stage 2 로그인 엔드포인트.

    성공 시 Bearer 토큰을 발급한다.
    """
    login_identity = request.username.strip() or None
    # d06 Add-on:
    # rate limit 은 인증보다 먼저 걸린다. 시도한 계정명을 미리 컨텍스트에 넣어두어야
    # 무차별 대입으로 429 에 막힌 요청에도 '누가 시도했는지'가 감사 이벤트에 남는다.
    audit.set_actor_hint(request.username)
    enforce_rate_limit(
        http_request,
        scope="login",
        max_requests=RATE_LIMIT_LOGIN_MAX,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        identity=login_identity,
    )
    user = auth_service.authenticate(request.username, request.password)
    if not user:
        # Stage 4 추가:
        # 로그인 실패는 보안 이벤트이므로 security.log 에 남긴다.
        # 비밀번호는 core/masking.py 에 의해 자동 마스킹된다.
        log_security_event(
            "login failed",
            {"username": request.username, "password": request.password, "path": http_request.url.path},
        )
        # d06 Add-on:
        # 실패한 로그인은 '시도한 사용자명'이 핵심 증적이므로 actor 로 남긴다.
        audit.record(
            action="auth_login_failed",
            asset="auth_service",
            result="failure",
            actor=request.username,
            role="unauthenticated",
            purpose="failed-login",
        )
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    token = auth_service.issue_token(user)
    # Stage 4 추가:
    # 로그인 성공도 보안 이벤트로 기록한다.
    # access_token 역시 자동 마스킹 대상이다.
    log_security_event(
        "login success",
        {"username": user["username"], "role": user["role"], "access_token": token},
    )
    audit.record(
        action="auth_login",
        asset="auth_service",
        result="success",
        user=user,
        purpose="user-login",
    )
    return {"access_token": token, "token_type": "bearer", "user": user}


@app.get("/auth/me")
def read_me(current_user: dict = Depends(require_login)) -> dict[str, object]:
    # Stage 4 추가:
    # 일반 조회성 API 접근은 app.log 에 기록한다.
    log_app_event("auth me", {"username": current_user["username"], "role": current_user["role"]})
    audit.record(
        action="read_profile",
        asset="auth_service",
        result="success",
        user=current_user,
        purpose="profile-view",
    )
    return {"user": current_user}


# Stage 2 추가:
# 아래 엔드포인트들은 이제 `require_login` 의존성을 통해
# 로그인 사용자만 접근할 수 있도록 보호된다.
@app.get("/documents")
def get_documents(current_user: dict = Depends(require_login)) -> dict[str, object]:
    # Stage 4 추가:
    # 문서 목록 조회 이벤트를 app.log 에 남긴다.
    log_app_event("documents viewed", {"username": current_user["username"]})
    audit.record(
        action="read_documents",
        asset="document_store",
        result="success",
        user=current_user,
        purpose="document-list",
    )
    docs = load_documents()
    return {
        "user": current_user,
        "count": len(docs),
        "documents": [{"doc_id": doc.doc_id, "text": doc.text} for doc in docs],
    }


@app.get("/tools")
def get_tools(current_user: dict = Depends(require_login)) -> dict[str, object]:
    # Stage 4 추가:
    # 도구 목록 조회 이벤트를 app.log 에 남긴다.
    log_app_event("tools viewed", {"username": current_user["username"]})
    audit.record(
        action="read_tools",
        asset="tool_registry",
        result="success",
        user=current_user,
        purpose="tool-list",
    )
    return {
        "user": current_user,
        "tools": [
            {"name": "tool_list_documents", "description": "문서 목록 조회"},
            {"name": "tool_document_summary", "description": "문서 구성 요약"},
            {"name": "tool_rag", "description": "RAG 검색 후 답변 생성"},
            {"name": "tool_direct_answer", "description": "문서 검색 없이 일반 답변 생성"},
        ]
    }


# Stage 3 추가:
# RAG 호출은 비용이 큰 편이므로 로그인 사용자 기준으로 별도 제한을 둔다.
@app.post("/rag")
def rag_answer(
    request: RagRequest,
    http_request: Request,
    current_user: dict = Depends(require_login),
) -> dict[str, object]:
    enforce_rate_limit(
        http_request,
        scope="rag",
        max_requests=RATE_LIMIT_RAG_MAX,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        identity=current_user["username"],
    )
    # d06: 인증된 사용자를 감사 턴 신원으로 결합한다.
    # 이게 없으면 턴 이벤트의 actor 가 기본값(anonymous)으로 남아 추적이 끊긴다.
    audit_turn.bind_request(
        actor=current_user["username"], role=current_user.get("role", "rag_user"),
        department=current_user.get("department", "ai-platform"),
        source_ip=http_request.client.host if http_request.client else "127.0.0.1")
    audit_turn.start_turn(request.question)
    try:
        answer = run_rag(request.question, top_k=request.top_k)
        audit_turn.end_turn(tool_name="tool_rag", result="success",
                            question=request.question)
    except BaseException as exc:
        # d06 Add-on:
        # 실패한 질의도 '무엇을 물었는가'가 감사 증적이다.
        # 요청당 감사 이벤트는 한 건이므로 실패 원인을 result 에 함께 담는다.
        audit.record(
            action="rag_query",
            asset="vector_index",
            result=f"failure:{exc.__class__.__name__}",
            user=current_user,
            purpose=request.question,
        )
        audit_turn.end_turn(tool_name="tool_rag",
                            result="error:{}".format(exc.__class__.__name__),
                            question=request.question)
        raise translate_error(exc) from exc
    # Stage 4 추가:
    # RAG 응답 성공 이벤트를 app.log 에 남긴다.
    log_app_event(
        "rag answered",
        {"username": current_user["username"], "question": request.question, "top_k": request.top_k},
    )
    # d06 Add-on:
    # purpose 에 질문 원문을 담는다. 감사엔진의 crypto_rules.target_pii_fields 가
    # ["actor", "purpose"] 이므로 질문과 사용자명이 Stage 3에서 자동 암호화된다.
    audit.record(
        action="rag_query",
        asset="vector_index",
        result="success",
        user=current_user,
        purpose=request.question,
    )
    return {
        "mode": "rag",
        "user": current_user,
        "question": request.question,
        "top_k": request.top_k,
        "answer": answer,
    }


@app.post("/agent")
def agent_answer(
    request: QuestionRequest,
    current_user: dict = Depends(require_login),
) -> dict[str, object]:
    audit_turn.bind_request(
        actor=current_user["username"], role=current_user.get("role", "rag_user"),
        department=current_user.get("department", "ai-platform"))
    try:
        trace = run_agent_with_trace(request.question)
    except BaseException as exc:
        audit.record(
            action="agent_invoke",
            asset="tool:unresolved",
            result=f"failure:{exc.__class__.__name__}",
            user=current_user,
            purpose=request.question,
        )
        raise translate_error(exc) from exc
    # Stage 4 추가:
    # Agent 응답 성공 이벤트를 app.log 에 남긴다.
    log_app_event(
        "agent answered",
        {"username": current_user["username"], "question": request.question, "tool_name": trace["tool_name"]},
    )
    # d06 Add-on:
    # 에이전트는 '어떤 도구를 골라 실행했는가'가 감사 대상 자산이다.
    audit.record(
        action="agent_invoke",
        asset=f"tool:{trace['tool_name']}",
        result="success",
        user=current_user,
        purpose=request.question,
    )
    return {"mode": "agent", "user": current_user, **trace}


# d06 미션 추가:
# 사용자 피드백 로그 — 자유입력에 섞여 들어오는 개인정보를 저장 전에 통제한다.
FEEDBACK_DIR = Path(__file__).resolve().parent / "feedback_out"
FEEDBACK_PATH = FEEDBACK_DIR / "feedback.jsonl"


@app.post("/feedback")
def submit_feedback(
    request: FeedbackRequest,
    current_user: dict = Depends(require_login),
) -> dict[str, object]:
    """피드백을 받아 개인정보를 통제한 뒤 적재한다.

    통제는 **저장 전에** 한다. 원문을 파일에 쓰고 나중에 지우는 방식은,
    지우기 전까지 평문이 디스크에 존재하고 백업에도 그대로 들어간다.
    """
    result = guard.process(request.comment, data_class=FEEDBACK_LOG)

    entry = {
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "record_id": request.record_id,
        "actor": current_user["username"],
        "rating": request.rating,
        # 통제된 본문만 적재한다. 원문은 어디에도 남기지 않는다.
        "comment": result.text,
        "pii_findings": result.summary(),
    }
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    with open(FEEDBACK_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    log_app_event("feedback submitted",
                  {"username": current_user["username"], "rating": request.rating})
    audit.record(
        action="feedback_submitted",
        asset="feedback_store",
        result="success",
        user=current_user,
        purpose="rating={} · PII 탐지 {}건".format(
            request.rating, result.summary()["total"]),
    )
    return {
        "stored": True,
        "record_id": request.record_id,
        "pii_controlled": result.changed,
        "pii_summary": result.summary(),
        "stored_comment": result.text,
    }


# Stage 2 추가:
# 관리자 전용 검증용 엔드포인트다. `require_admin` 동작 확인용으로 사용한다.
# Stage 3 추가:
# 관리자 경로도 민감 경로이므로 관리자 사용자명 기준 요청 제한을 적용한다.
@app.get("/admin/config")
def admin_config_limited(
    http_request: Request,
    current_user: dict = Depends(require_admin),
) -> dict[str, object]:
    """Stage 3 rate limit가 적용된 관리자 검증용 엔드포인트."""
    enforce_rate_limit(
        http_request,
        scope="admin",
        max_requests=RATE_LIMIT_ADMIN_MAX,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        identity=current_user["username"],
    )
    # Stage 4 추가:
    # 관리자 설정 조회는 민감 경로 접근이므로 security.log 에 기록한다.
    log_security_event("admin config viewed", {"username": current_user["username"], "role": current_user["role"]})
    audit.record(
        action="admin_config_read",
        asset="config_store",
        result="success",
        user=current_user,
        purpose="admin-access",
    )
    return {
        "message": "관리자 전용 설정 정보입니다.",
        "user": current_user,
        "protected_values": {
            "documents_path": str(DOCUMENTS_PATH),
            "chat_model": CHAT_MODEL,
            "embed_model": EMBED_MODEL,
        },
    }


# Stage 6 추가:
# 공통 예외 처리 동작을 검증하기 위한 관리자 전용 강제 예외 엔드포인트다.
@app.get("/admin/test-error")
def admin_test_error(current_user: dict = Depends(require_admin)) -> dict[str, object]:
    raise RuntimeError(f"forced test exception by {current_user['username']}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)



