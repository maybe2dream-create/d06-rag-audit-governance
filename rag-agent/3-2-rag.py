"""rag-agent/3-2-rag.py — RAG 코어 (문서 → 임베딩 → 검색 → 프롬프트 → 답변).

d06 감사 계측:
  ② retrieval  검색된 문서마다 asset=rag_doc:<id>, _detail{score, rank}
  ③a llm_call  RAG 경로 egress (_detail.path=rag)

턴 시작(①)과 종료(④)는 4-agent.py 가 담당한다.

실행:
  RAG_PROVIDER=local python3 -c "import importlib.util; ..."   # 4-agent.py 경유 권장
"""

from __future__ import annotations

import hashlib
import re
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.config import (  # noqa: E402
    DOCUMENTS_PATH, GEMINI_API_KEY, GEMINI_EMBED_MODEL, GEMINI_MODEL, RAG_PROVIDER,
)
from core.audit_setup import audit_turn  # noqa: E402
from core.pii_setup import TRAINING_DATA, guard  # noqa: E402

API_KEY = GEMINI_API_KEY
CHAT_MODEL = GEMINI_MODEL
EMBED_MODEL = GEMINI_EMBED_MODEL

SYSTEM_INSTRUCTION = (
    "당신은 RAG 어시스턴트입니다. "
    "제공된 Context 범위 안에서만 한국어로 간결히 답합니다."
)


# =============================================================================
# 1. Document
# =============================================================================
@dataclass
class Document:
    doc_id: str
    text: str


def load_documents() -> List[Document]:
    """문서를 읽어 개인정보 통제를 적용한 뒤 반환한다.

    임베딩 **전에** 가려야 벡터DB와 LLM 컨텍스트에 원본 PII 가 들어가지 않는다.
    임베딩 이후에 가리는 것은 이미 나간 뒤라 의미가 없다.
    """
    rows = json.loads(DOCUMENTS_PATH.read_text(encoding="utf-8"))

    documents: List[Document] = []
    for row in rows:
        result = guard.process(row["text"], data_class=TRAINING_DATA)
        if result.blocked:
            continue
        documents.append(Document(doc_id=row["doc_id"], text=result.text))
    return documents


# =============================================================================
# 2. Embeddings
# =============================================================================
def local_embed(text: str) -> List[float]:
    """스텁 임베딩 — 어휘 해시 기반 bag-of-words.

    토큰마다 해시로 차원을 골라 가중치를 더한다. 순수 문자열 해시와 달리 **겹치는
    단어가 많을수록 코사인 유사도가 올라가므로** 검색이 의미 있게 동작한다.
    이게 필요한 이유: 순수 해시 임베딩은 회수 문서가 사실상 무작위라
    "연봉 질문 → hr_salary 회수 → 등급 부족 거부" 같은 시나리오를 검증할 수 없다.

    의미 임베딩은 아니다. 동의어·문맥은 잡지 못하므로 검색 품질은 보장하지 않고,
    실제 품질 확인은 Gemini 경로에서 해야 한다.
    """
    dims = 64
    vector = [0.0] * dims
    tokens = [t for t in re.split(r"[^0-9A-Za-z가-힣]+", text.lower()) if t]
    for token in tokens:
        # 한국어는 조사가 붙으므로 앞 2글자 어간도 함께 넣어 부분 일치를 잡는다.
        for form in {token, token[:2]}:
            if not form:
                continue
            digest = hashlib.sha256(form.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % dims
            vector[index] += 1.0
    return vector


def require_gemini():
    if not API_KEY:
        print("GEMINI_API_KEY 가 필요합니다.", file=sys.stderr)
        sys.exit(1)
    try:
        import google.generativeai as genai
    except ImportError:
        print("패키지 필요: pip install google-generativeai", file=sys.stderr)
        sys.exit(1)
    genai.configure(api_key=API_KEY)
    return genai


def get_provider():
    """(genai, model_name) 반환. local 이면 genai 는 None."""
    if RAG_PROVIDER == "local":
        return None, "stub-local"
    return require_gemini(), CHAT_MODEL


def embed_text(genai, text: str) -> List[float]:
    if genai is None:
        return local_embed(text)
    result = genai.embed_content(model=EMBED_MODEL, content=text,
                                 task_type="retrieval_document")
    return list(result["embedding"] if isinstance(result, dict) else result.embedding)


def embed_query(genai, text: str) -> List[float]:
    if genai is None:
        return local_embed(text)
    result = genai.embed_content(model=EMBED_MODEL, content=text,
                                 task_type="retrieval_query")
    return list(result["embedding"] if isinstance(result, dict) else result.embedding)


# =============================================================================
# 3. Vector DB
# =============================================================================
@dataclass
class VectorRecord:
    document: Document
    embedding: List[float]


class InMemoryVectorDB:
    def __init__(self) -> None:
        self._rows: List[VectorRecord] = []

    def add(self, document: Document, embedding: Sequence[float]) -> None:
        self._rows.append(VectorRecord(document=document, embedding=list(embedding)))

    def all(self) -> List[VectorRecord]:
        return list(self._rows)


def build_index(genai, documents: List[Document]) -> InMemoryVectorDB:
    db = InMemoryVectorDB()
    for doc in documents:
        db.add(doc, embed_text(genai, doc.text))
    return db


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if na == 0.0 or nb == 0.0 else dot / (na * nb)


def search(genai, db: InMemoryVectorDB, query: str,
           top_k: int = 2) -> List[Tuple[Document, float]]:
    """검색 후 회수된 문서마다 감사 이벤트 ②를 남긴다.

    회수된 문서가 곧 LLM 에게 넘어간 자료다. 유출 사고 조사에서 가장 먼저
    확인해야 할 기록이므로 score·rank 까지 함께 남긴다.
    """
    q_vec = embed_query(genai, query)
    scored = [(row.document, cosine_similarity(q_vec, row.embedding)) for row in db.all()]
    scored.sort(key=lambda x: x[1], reverse=True)
    hits = scored[:top_k]

    for rank, (doc, score) in enumerate(hits, start=1):
        audit_turn.retrieval(doc_id=doc.doc_id, score=score, rank=rank, question=query)
    return hits


# =============================================================================
# 4. RAG
# =============================================================================
def build_prompt(question: str, contexts: List[Document]) -> str:
    if not contexts:
        context_block = "(관련 문서 없음)"
    else:
        context_block = "\n".join("[{}] {}".format(c.doc_id, c.text) for c in contexts)

    return """다음 Context 만 근거로 질문에 답하세요.
Context 에 없는 내용은 추측하지 말고 '문서에 없습니다'라고 하세요.

--- Context ---
{}
---

Question: {}
""".format(context_block, question)


def local_answer(user_prompt: str, question: str = "") -> str:
    if user_prompt:
        body = user_prompt.split("--- Context ---")[-1].split("---")[0].strip()
        return "[local-stub] 회수된 Context 기준 응답입니다.\n{}".format(body[:400])
    return "[local-stub] '{}' 에 대한 테스트 응답입니다.".format(question)


def generate_answer(genai, user_prompt: str, question: str = "",
                    model_name: str = "") -> str:
    """③a RAG 경로 egress. 조직 데이터가 모델 제공자에게 나가는 지점이다."""
    model_name = model_name or (CHAT_MODEL if genai is not None else "stub-local")
    audit_turn.llm_call(model=model_name, path="rag", question=question)

    if genai is None:
        return local_answer(user_prompt, question)

    model = genai.GenerativeModel(model_name=model_name,
                                  system_instruction=SYSTEM_INSTRUCTION)
    response = model.generate_content(user_prompt, generation_config={"temperature": 0.2})
    text = getattr(response, "text", None)
    return text.strip() if text else "[Gemini] 빈 응답"


def generate_direct_answer(question: str) -> str:
    """③b 일반 답변 경로 egress.

    ③a 만 계측하면 이 경로가 통째로 감사에서 빠진다. 문서를 안 거쳤을 뿐
    조직 밖으로 나간 것은 똑같다. T-04 가 이 회귀를 잡는 항목이다.
    """
    genai, model_name = get_provider()
    audit_turn.llm_call(model=model_name, path="direct", question=question)

    if genai is None:
        return "[local-stub] '{}' 에 대한 일반 답변입니다.".format(question)

    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction="당신은 간단한 학습용 에이전트입니다. 한국어로 짧게 답하세요.")
    response = model.generate_content(question, generation_config={"temperature": 0.2})
    text = getattr(response, "text", None)
    return text.strip() if text else "[Gemini] 빈 응답"


def run_rag(question: str, top_k: int = 2) -> str:
    documents = load_documents()
    genai, model_name = get_provider()
    db = build_index(genai, documents)
    hits = search(genai, db, question, top_k=top_k)
    contexts = [doc for doc, _score in hits]
    prompt = build_prompt(question, contexts)
    return generate_answer(genai, prompt, question, model_name)
