"""Stage 2 요청/응답 스키마 모음."""

from pydantic import BaseModel, Field


class QuestionRequest(BaseModel):
    # Stage 2 추가:
    # 질문 입력 스키마를 `app.py` 밖으로 분리해 재사용한다.
    question: str = Field(..., description="사용자 질문")


class RagRequest(QuestionRequest):
    # Stage 2 추가:
    # RAG 요청에서만 필요한 `top_k` 값을 별도 정의한다.
    top_k: int = Field(2, ge=1, le=10, description="검색할 상위 문서 수")


class LoginRequest(BaseModel):
    # Stage 2 추가:
    # 로그인 요청 바디를 명시적으로 검증하기 위한 스키마다.
    username: str = Field(..., min_length=1, max_length=100, description="로그인 아이디")
    password: str = Field(..., min_length=1, max_length=100, description="로그인 비밀번호")


class FeedbackRequest(BaseModel):
    # d06 미션 추가:
    # comment 는 사용자 자유입력이라 개인정보 유입의 주 경로다.
    # 저장 전에 pii_guard 로 통제한다.
    record_id: str = Field(..., min_length=1, max_length=64,
                           description="피드백 대상 요청의 record_id")
    rating: int = Field(..., ge=1, le=5, description="만족도 1~5")
    comment: str = Field("", max_length=2000, description="자유 입력 의견")
