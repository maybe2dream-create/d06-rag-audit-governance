"""rag-agent/4-agent.py — 도구 선택과 실행 (Agent).

d06 감사 계측:
  ① agent_query   턴 시작
  ③b llm_call     일반 답변 경로 egress (3-2-rag.py 의 generate_direct_answer 안)
  ④ agent_result  턴 종료

실행:
  RAG_PROVIDER=local python3 rag-agent/4-agent.py       # 내장 데모 질문
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Callable, Dict, Tuple

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

from core.audit_setup import audit_turn  # noqa: E402


# =============================================================================
# 도구
# =============================================================================
def tool_list_documents() -> str:
    docs = RAG.load_documents()
    lines = ["[도구] 문서 목록 조회"]
    for doc in docs:
        lines.append("- {}: {}".format(doc.doc_id, doc.text))
    return "\n".join(lines)


def tool_document_summary() -> str:
    docs = RAG.load_documents()
    return "\n".join([
        "[도구] 문서 구성 요약",
        "- 문서 수: {}".format(len(docs)),
        "- 문서 id: {}".format(", ".join(doc.doc_id for doc in docs)),
    ])


def tool_rag(question: str) -> str:
    return RAG.run_rag(question, top_k=2)


def tool_direct_answer(question: str) -> str:
    return RAG.generate_direct_answer(question)


# =============================================================================
# 라우팅
# =============================================================================
# 키워드 우선순위. 위에서부터 먼저 걸리는 규칙이 이긴다.
# 주의: "요약" 이 1순위라 "연봉 정책 요약해줘" 는 RAG 가 아니라 summary 로 간다.
def choose_action(question: str) -> Tuple[str, Callable[..., str]]:
    lowered = question.lower()

    if any(k in question for k in ["몇 개", "구성", "종류", "요약"]):
        return ("문서 구성을 먼저 요약하는 것이 맞음", tool_document_summary)

    if any(k in question for k in ["문서", "목록", "documents"]):
        return ("문서 목록을 먼저 보여주는 것이 맞음", tool_list_documents)

    if any(k in question for k in ["날씨", "지원", "환불", "정책", "고객", "주말"]):
        return ("문서 기반 질문이라 RAG 도구를 사용", tool_rag)

    if any(k in lowered for k in ["weather", "support", "refund", "policy"]):
        return ("영문이지만 문서 검색 주제라 RAG 도구를 사용", tool_rag)

    return ("문서 검색보다 일반 답변이 더 적절함", tool_direct_answer)


# =============================================================================
# 실행
# =============================================================================
def run_agent_with_trace(question: str) -> Dict[str, str]:
    """한 턴을 실행하고 시작·종료를 감사에 남긴다.

    실패해도 반드시 end_turn 을 부른다. 턴이 열린 채로 끝나면 감사 로그만 보고는
    처리 중 죽은 것인지 응답을 준 것인지 구분할 수 없다 (T-22).
    """
    turn_id = audit_turn.start_turn(question)
    reason, action = choose_action(question)

    try:
        result = action(question) if action in (tool_rag, tool_direct_answer) else action()
    except BaseException as exc:                       # noqa: BLE001
        audit_turn.end_turn(tool_name=action.__name__,
                            result="error:{}".format(exc.__class__.__name__),
                            question=question)
        raise

    audit_turn.end_turn(tool_name=action.__name__, result="success", question=question)
    return {
        "turn_id": turn_id,
        "question": question,
        "reason": reason,
        "tool_name": action.__name__,
        "result": result,
    }


def run_agent(question: str) -> str:
    return run_agent_with_trace(question)["result"]


DEMO_QUESTIONS = [
    "문서 목록 보여줘",
    "문서 구성 요약해줘",
    "주말에 고객 지원 받을 수 있어?",
    "파이썬은 어떤 언어야?",
    "제 번호는 010-1234-5678 인데 환불 가능한가요?",
]


def main() -> int:
    print("=" * 72)
    print(" [4-agent] Agent 데모 — 감사 계측 확인")
    print("=" * 72)
    for question in DEMO_QUESTIONS:
        trace = run_agent_with_trace(question)
        print("\n[질문] {}".format(question))
        print("  판단   : {}".format(trace["reason"]))
        print("  도구   : {}".format(trace["tool_name"]))
        print("  turn_id: {}".format(trace["turn_id"]))
        print("  응답   : {}".format(trace["result"].replace("\n", " ")[:100]))
    print("\n감사 싱크: {}".format(audit_turn.sink.path_for()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
