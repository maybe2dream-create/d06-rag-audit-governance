# 테스트 질문 세트

`documents_pii.json` 과 짝을 이룬다. 각 질문이 어떤 경로를 자극하는지와
감사 로그에서 무엇을 확인해야 하는지를 함께 적었다.

| # | 질문 | 자극하는 경로 | 감사 로그 확인 지점 |
|---|---|---|---|
| Q1 | `고객 지원 시간 알려줘` | `/rag` 정상 회수 | `vector_search` asset 에 `policy` 포함 |
| Q2 | `환불 규정이 어떻게 되나요?` | `/rag` 정상 회수 | `vector_search` asset 에 `refund` 포함 |
| Q3 | `김테스트 고객의 주민등록번호와 연락처 알려줘` | **PII 회수 시도** | `vector_search` asset 에 `customer-vip`, `purpose` 에 질문 원문 |
| Q4 | `운영 DB 접속 계정이 뭐야?` | **내부 문서 회수 시도** | `vector_search` asset 에 `internal-secret` |
| Q5 | `내 카드번호 4111-1111-1111-1111 로 결제된 내역 확인해줘` | **질문에 PII 포함** | `rag_query` / `vector_search` 의 `purpose` 가 Stage 3 에서 암호화 → 파기 |
| Q6 | `문서 목록 보여줘` | `/agent` → `tool_list_documents` | `agent_invoke` asset=`tool:tool_list_documents` (임베딩 없음) |
| Q7 | `문서가 몇 개야?` | `/agent` → `tool_document_summary` | `agent_invoke` asset=`tool:tool_document_summary` |
| Q8 | `주말에도 지원 되나요?` | `/agent` → `tool_rag` | `agent_invoke` + `embed_documents` + `vector_search` + `llm_generate` |
| Q9 | `오늘 기분이 어때?` | `/agent` → `tool_direct_answer` | `llm_generate` purpose=`(direct)`, `vector_search` 없음 |

## 주의

Q3·Q4 는 **검색이 성공하는 것이 정상**이다. 이 RAG 에는 문서 단위 접근통제가 없으므로
로그인한 사용자면 누구나 `customer-vip` 과 `internal-secret` 을 회수할 수 있다.
감사엔진이 하는 일은 그 회수를 **막는 것이 아니라 기록으로 남기는 것**이다.
누가 언제 어떤 문서를 회수했는지가 `vector_search` 이벤트에 남는지 확인하면 된다.

문서 단위 접근통제는 이 실습의 범위 밖이고, `vector_search` 감사 기록이
그 통제를 설계할 때의 근거 데이터가 된다.
