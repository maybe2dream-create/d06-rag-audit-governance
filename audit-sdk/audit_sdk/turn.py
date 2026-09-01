"""턴 단위 감사 계측 API.

RAG 에이전트의 한 번의 문답(턴)을 다섯 지점에서 기록한다.

    ① agent_query   턴 시작 — 무엇을 물었는가
    ② retrieval     검색 근거 — 어떤 문서가 회수되었는가 (asset=rag_doc:<id>)
    ③a llm_call     RAG 경로 egress  (_detail.path=rag)
    ③b llm_call     일반 답변 경로 egress (_detail.path=direct)
    ④ agent_result  턴 종료 — 어떤 도구로 끝났는가

■ ③b 를 빠뜨리기 쉽다:
  RAG 경로만 계측하면 `tool_direct_answer` 로 나간 응답은 감사 기록이 통째로 없다.
  문서를 안 거쳤을 뿐 조직 밖(모델 제공자)으로 나간 것은 똑같다. 두 경로 모두 계측한다.

■ 기록 시점에 통제한다:
  PII 마스킹과 actor 가명처리는 append 직전에 적용한다. 원문을 파일에 쓰고 나중에
  지우는 방식은 지우기 전까지 평문이 디스크에 남고 백업에도 그대로 들어간다.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .access import AccessGuardEngine, DataClassifier
from .chain import ChainSink
from .event import AUDIT_FIELDS

# 계측 지점의 action 이름
ACTION_QUERY = "agent_query"
ACTION_RETRIEVAL = "retrieval"
ACTION_LLM_CALL = "llm_call"
ACTION_RESULT = "agent_result"

DEFAULT_IDENTITY = {
    "actor": "anonymous",
    "role": "rag_user",
    "department": "ai-platform",
    "source_ip": "127.0.0.1",
}


def _pseudonym_key() -> bytes:
    raw = os.getenv("AUDIT_PSEUDONYM_KEY", "").strip()
    return raw.encode("utf-8") if raw else secrets.token_bytes(32)


class AuditTurnRecorder:
    """턴 단위 감사 기록기. 모듈 전역 `audit` 인스턴스로 쓴다."""

    def __init__(self, sink_dir=None, access_policy_path=None, pii_guard=None):
        base = Path(__file__).resolve().parent.parent.parent   # d06/
        self.sink_dir = Path(sink_dir) if sink_dir else base / "audit-events"
        self._sink: Optional[ChainSink] = None

        policy_path = access_policy_path or (
            base / "configs" / "lab10_access_control_policy.json")
        self.guard = AccessGuardEngine.load(policy_path)
        self.classifier = DataClassifier.from_guard(self.guard)

        # PII 탐지·마스킹기. 없으면 마스킹 없이 기록한다(테스트 편의).
        self.pii_guard = pii_guard
        self._pseudonym_key = _pseudonym_key()

        self.identity: Dict[str, str] = dict(DEFAULT_IDENTITY)
        self.turn_id: str = ""
        self.seq: int = 0
        self.denials: List[Dict[str, Any]] = []

    # ------------------------------------------------------------ 싱크
    @property
    def sink(self) -> ChainSink:
        # sink_dir 를 나중에 바꿔치기하는 테스트(T-21)를 위해 매번 확인한다.
        if self._sink is None or self._sink.sink_dir != Path(self.sink_dir):
            self._sink = ChainSink(self.sink_dir)
        return self._sink

    # ------------------------------------------------------------ 신원
    def bind_request(self, actor: str = "", role: str = "", department: str = "",
                     source_ip: str = "") -> Dict[str, str]:
        """이번 요청의 신원을 고정한다. 인증 계층이 없을 때 주입값으로 쓴다."""
        self.identity = {
            "actor": actor or DEFAULT_IDENTITY["actor"],
            "role": role or DEFAULT_IDENTITY["role"],
            "department": department or DEFAULT_IDENTITY["department"],
            "source_ip": source_ip or DEFAULT_IDENTITY["source_ip"],
        }
        return self.identity

    # ------------------------------------------------------------ 통제
    def _pseudonymize(self, actor: str) -> str:
        """actor 가명처리. 같은 사용자는 같은 토큰이 되어 추적은 되고 식별은 안 된다."""
        digest = hmac.new(self._pseudonym_key, actor.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        return "u_{}".format(digest[:12])

    def _mask(self, text: str) -> str:
        """기록 직전 PII 마스킹. [RRN_MASKED] 같은 토큰으로 치환한다."""
        if not text or self.pii_guard is None:
            return text
        try:
            return self.pii_guard.tokenize(text)
        except Exception:  # noqa: BLE001 - 마스킹 실패가 기록을 막지 않는다
            return text

    # ------------------------------------------------------------ 기록
    def _next_record_id(self) -> str:
        self.seq += 1
        return "rag-{}-{}".format(self.turn_id or "notrun", self.seq)

    def _emit(self, action: str, asset: str, purpose: str, result: str,
              detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        decision = self.guard.authorize(
            action=action, asset=asset,
            actor=self.identity["actor"], role=self.identity["role"],
            department=self.identity["department"])

        if not decision.allowed:
            self.denials.append(decision.to_dict())
            result = "denied"

        event = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": self._pseudonymize(self.identity["actor"]),
            "role": self.identity["role"],
            "department": self.identity["department"],
            "action": action,
            "asset": asset,
            "record_id": self._next_record_id(),
            "source_ip": self.identity["source_ip"],
            "purpose": self._mask(purpose),
            "result": result,
        }
        event = {field: event.get(field, "") for field in AUDIT_FIELDS}

        detail = dict(detail or {})
        detail["classification"] = self.classifier.classify(asset) if asset else "n/a"
        if not decision.allowed:
            detail["deny_reasons"] = decision.reasons

        self.sink.append(event, detail)
        return event

    # ------------------------------------------------------------ 계측 지점
    def start_turn(self, question: str) -> str:
        """① 턴 시작."""
        self.turn_id = uuid.uuid4().hex[:8]
        self.seq = 0
        self.denials = []
        self._emit(ACTION_QUERY, asset="", purpose=question, result="received")
        return self.turn_id

    def retrieval(self, doc_id: str, score: float = 0.0, rank: int = 0,
                  question: str = "") -> Dict[str, Any]:
        """② 검색 근거. 회수된 문서가 곧 LLM 에 넘어간 자료다."""
        return self._emit(
            ACTION_RETRIEVAL,
            asset="rag_doc:{}".format(doc_id),
            purpose=question or "document retrieval",
            result="retrieved",
            detail={"score": round(float(score), 4), "rank": rank},
        )

    def llm_call(self, model: str, path: str = "rag",
                 question: str = "") -> Dict[str, Any]:
        """③ 모델 호출 — 조직 데이터가 밖으로 나가는 지점(egress)."""
        return self._emit(
            ACTION_LLM_CALL,
            asset="llm:{}".format(model),
            purpose=question or "llm generation",
            result="called",
            detail={"path": path, "model": model},
        )

    def end_turn(self, tool_name: str, result: str = "success",
                 question: str = "") -> Dict[str, Any]:
        """④ 턴 종료. 실패해도 반드시 호출해 턴이 열린 채 끝나지 않게 한다(T-22)."""
        return self._emit(
            ACTION_RESULT,
            asset="agent:{}".format(tool_name),
            purpose=question or "agent turn complete",
            result=result,
            detail={"tool_name": tool_name, "denials": len(self.denials)},
        )


def build_recorder(pii_guard=None) -> AuditTurnRecorder:
    return AuditTurnRecorder(pii_guard=pii_guard)
