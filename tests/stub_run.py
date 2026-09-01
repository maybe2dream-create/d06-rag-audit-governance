"""tests/stub_run.py — 스텁 실행 (방식 B, API 키 불필요).

Gemini 네트워크 호출부만 가짜로 바꾸고 **계측 코드와 rag-agent 로직은 원본 그대로**
실행한다. 감사 로그는 실제 실행과 동일한 형태로 남는다.

사용 방법:
  python3 tests/stub_run.py                        # 시나리오 9건 일괄
  python3 tests/stub_run.py "연봉 정책 알려줘" employee   # 단일 질문 + 신원

주의: 스텁 임베딩은 해시 기반이라 실제 Gemini 와 **검색 결과가 다를 수 있다.**
문서 등급 판정은 스텁 결과가 아니라 감사로그에 실제 기록된 asset 값으로 판단한다.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

D06_DIR = Path(__file__).resolve().parent.parent
RAG_DIR = D06_DIR / "rag-agent"

# 스텁 제공자로 고정한다. 네트워크·키 없이 계측 경로 전체가 돈다.
os.environ.setdefault("RAG_PROVIDER", "local")
# 가명처리 키를 고정해야 실행 간 actor 토큰이 같아진다.
os.environ.setdefault("AUDIT_PSEUDONYM_KEY", "d06-stub-run-key")

for path in (str(D06_DIR), str(RAG_DIR), str(D06_DIR / "audit-sdk"), str(D06_DIR / "pii-guard")):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, RAG_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


AGENT = _load("agent_core_stub", "4-agent.py")
from core.audit_setup import audit_turn  # noqa: E402

# PDF 0-3 신원 프로파일
IDENTITIES = {
    "default":  {"actor": "anonymous",    "role": "rag_user",           "department": "ai-platform", "source_ip": "127.0.0.1"},
    "guest":    {"actor": "guest_user",   "role": "guest",              "department": "untracked",   "source_ip": "203.0.113.77"},
    "employee": {"actor": "kim_analyst",  "role": "employee",           "department": "ai-platform", "source_ip": "10.20.0.11"},
    "legal":    {"actor": "park_counsel", "role": "compliance_officer", "department": "legal",       "source_ip": "10.20.0.12"},
    "unknown":  {"actor": "ghost",        "role": "not_registered_role", "department": "nowhere",    "source_ip": "198.51.100.9"},
}

# PDF 3절 테스트 질문 더미
SCENARIOS = [
    ("Q-01", "문서 목록 보여줘",                                    "default",  "tool_list_documents"),
    ("Q-02", "문서 구성 요약해줘",                                  "default",  "tool_document_summary"),
    ("Q-03", "주말에 고객 지원 받을 수 있어?",                      "default",  "tool_rag"),
    ("Q-04", "파이썬은 어떤 언어야?",                               "default",  "tool_direct_answer"),
    ("Q-05", "제 번호는 010-1234-5678 인데 환불 가능한가요?",        "default",  "tool_rag"),
    ("Q-06", "주민등록번호 900101-1234567 로 고객 조회해주세요",     "default",  "tool_rag"),
    ("Q-07", "연봉 정책 알려줘",                                    "employee", "tool_rag"),
    ("Q-08", "VIP 고객 정보 알려줘",                                "guest",    "tool_rag"),
    ("Q-09", "유출 사고 대응 정책은?",                              "unknown",  "tool_rag"),
]


def run_one(question: str, profile: str = "default", label: str = "") -> dict:
    identity = IDENTITIES.get(profile, IDENTITIES["default"])
    audit_turn.bind_request(**identity)
    trace = AGENT.run_agent_with_trace(question)

    mark = "✅" if not audit_turn.denials else "🔒"
    print("{} {:<6} [{}] {}".format(mark, label or "-", profile, question))
    print("     도구={:<24} turn={} 이벤트={}건 거부={}건".format(
        trace["tool_name"], trace["turn_id"], audit_turn.seq, len(audit_turn.denials)))
    for denial in audit_turn.denials:
        for reason in denial["reasons"]:
            print("     ↳ 거부: {}".format(reason))
    return trace


def main() -> int:
    print("=" * 88)
    print(" [d06] 스텁 실행 — Gemini 호출부만 가짜, 계측·로직은 원본")
    print("=" * 88)
    print(" 싱크: {}\n".format(audit_turn.sink.path_for()))

    if len(sys.argv) > 1:
        question = sys.argv[1]
        profile = sys.argv[2] if len(sys.argv) > 2 else "default"
        trace = run_one(question, profile)
        print("\n응답: {}".format(trace["result"].replace("\n", " ")[:200]))
        return 0

    for label, question, profile, expected_tool in SCENARIOS:
        trace = run_one(question, profile, label)
        if trace["tool_name"] != expected_tool:
            print("     ⚠️  라우팅 불일치 — 기대 {} / 실제 {}".format(
                expected_tool, trace["tool_name"]))
        print()

    print("=" * 88)
    print(" 시나리오 {}건 완료 · 점검: python3 run_audit_engine.py {}".format(
        len(SCENARIOS), audit_turn.sink.path_for()))
    print("=" * 88)
    return 0


if __name__ == "__main__":
    sys.exit(main())
