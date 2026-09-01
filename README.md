# d06 — RAG 시스템 + 감사엔진 Add-on

RAG 서비스가 남기는 기록에 **무결성·보관정책·PII 통제**를 붙인다.
두 모듈을 별도 폴더로 가져와 **SDK 방식**으로 연동했다 (전송은 배치).

## 출처

| 폴더 | 출처 | 수정 여부 |
|---|---|---|
| `rag-agent/` | ch01/d05 rag-agent (`/Users/goorm/done`) | 감사 SDK 연동 |
| `audit-engine/audit_engine/` | ch03/d05 `Aug31/src/audit_engine` | **무수정** |
| `audit-engine/configs/` | 〃 `Aug31/configs` | 경로·보관정책·파기대상만 조정 |
| `audit-sdk/` | 신규 | 감사 기록 SDK — 앱이 쓰는 재사용 패키지 |

원본 두 경로는 **읽기만** 했고 변경하지 않았다.

## 왜 붙였나

기존 RAG는 `app.log` / `security.log` 텍스트 로그가 전부였다. 빠진 것:

1. **무결성** — 로그를 고쳐도 흔적이 없다
2. **보관정책** — 무엇을 얼마나 보관할 근거가 없다
3. **PII 통제** — `core/masking.py`는 `password`/`token` 키만 가린다. 질문과 사용자명은 평문

## 구조

연동방식은 **SDK**다. 감사 기록의 계약·적재·통제를 `audit-sdk` 가 소유하고, RAG 앱은 쓰기만 한다.

```
rag-agent/3-2-rag.py   RAG 코어      → ② retrieval  ③a llm_call(path=rag)
rag-agent/4-agent.py   도구 선택·실행 → ① agent_query ③b llm_call(path=direct) ④ agent_result
rag-agent/5-api.py     FastAPI 진입점 → 사용자 컨텍스트를 감사 턴에 결합
        ↓ audit_sdk (기록 시점에 통제 + 해시체인)
audit-events/rag_audit_<YYYYMMDD>.jsonl
        ↓ run_audit_engine.py     체인 검증 · PII · 접근제어 · 보관기한 점검
```

한 줄 구조:

```json
{"event": {5W1H 10필드}, "previous_hash": "...", "entry_hash": "...", "_detail": {...}}
```

**기록 시점에 통제한다.** PII 마스킹(`[RRN_MASKED]`), actor 가명처리, 해시체인 결합이
append 직전에 일어난다. 원문을 쓰고 나중에 지우는 방식은 지우기 전까지 평문이 디스크에
남고 백업에도 그대로 들어간다.

**해시 대상은 `event` 10필드뿐이다.** `_detail`(score·rank·path·tool_name)은 해시에
들어가지 않는 잔여위험이다. 핵심 식별자(doc_id·model)는 `asset` 에 넣어 보호한다.

### 접근통제 — deny-by-default

`configs/lab10_access_control_policy.json` 에 등록되지 않은 자산·role 은 **거부**로 판정한다.
등록 누락을 조용히 통과시키면 정책이 있으나 마나가 되기 때문이다.
거부 사유 5종: 등급 부족(RBAC) · 미등록 자산 · 미등록 role · 액션 권한 · 부서 제한(ABAC).

관찰 전용(PEP 없음)이라 거부가 기록돼도 응답은 정상 반환한다.
집행이 필요하면 `enforcement_mode` 를 `enforce` 로 바꾼다.

## 감사 이벤트 16종

| action | 트리거 | 보관 | 근거 |
|---|---|---|---|
| `auth_login` | 로그인 성공 | 365일 | 개인정보보호법 / ISMS-P |
| `auth_login_failed` | 로그인 실패 | 365일 | ISMS-P 접근통제 |
| `read_profile` | `/auth/me` | 365일 | 내부 보안 정책 |
| `read_documents` | `/documents` | 730일 | 개인정보보호법 시행령 §31 |
| `read_tools` | `/tools` | 365일 | 내부 보안 정책 |
| `rag_query` | `/rag` | 730일 | 개인정보보호법 시행령 §31 |
| `agent_invoke` | `/agent` | 730일 | 〃 / OWASP LLM Top 10 |
| `admin_config_read` | `/admin/config` | 1825일 | 전자금융거래법 / SOC 2 |
| `access_denied` | 401·403 | 1095일 | 침해사고 포렌식 |
| `rate_limit_block` | 429 | 1095일 | 〃 |
| `input_validation_failed` | 422 | 1095일 | 정보통신망법 |
| `app_error` | 5xx | 1095일 | ISMS-P 장애 대응 |
| `embed_documents` | 문서 임베딩 | 730일 | 개인정보보호법 §28-8 국외이전 |
| `vector_search` | 벡터 검색 회수 | 730일 | 시행령 §31 / OWASP LLM Top 10 |
| `llm_generate` | LLM 호출 | 730일 | 개인정보보호법 §28-8 국외이전 |
| `test_provider_used` | `RAG_PROVIDER=local` | 1095일 | ISMS-P 운영환경 무결성 |

`purpose`에 질문 원문이 들어간다. 엔진의 `target_pii_fields`가 `["actor","purpose"]`이므로
**질문과 사용자명이 Stage 3에서 자동 암호화**된다.

### RAG 동작 자체를 남긴다

`/rag` 한 번이 다섯 건의 상관된 이벤트를 만든다:

```
req-abc12345     test_provider_used   (local 모드일 때만)
req-abc12345.2   embed_documents      문서 6건 임베딩 (model=…, docs=…)
req-abc12345.3   vector_search        vector_index:customer-vip,internal-secret
req-abc12345.4   llm_generate         llm:gemini-2.5-flash
req-abc12345.5   rag_query            vector_index
```

`vector_search`의 asset에 남는 **회수된 문서 목록이 곧 LLM에게 넘어간 자료**다.
유출 사고 조사에서 가장 먼저 볼 기록이다. 접두사가 같아 한 요청으로 묶이고,
`.2` `.3` 접미사로 `record_id`는 서로 다르다.

### 파기는 네 action을 함께 해야 성립한다

같은 질문이 `rag_query` / `agent_invoke` / `vector_search` / `llm_generate` 의
`purpose`에 동일하게 남는다. 하나만 파기하면 나머지에서 그대로 복원되므로
Crypto-Shredding이 형식에 그친다. `shred_target_actions`에 넷을 모두 넣어야 한다.

### 미들웨어가 필요한 이유

`require_login` / `require_admin`이 거부한 요청은 엔드포인트 본문에 **들어오지 않는다.**
핸들러에서만 기록하면 권한 없는 접근 시도가 감사 로그에 통째로 빠진다.
그래서 `audit_sdk.integrations.fastapi`의 미들웨어가 401·403·422·429·5xx를 대신 남긴다.
성공 요청은 핸들러가 직접 남기므로 중복되지 않는다 (요청당 감사 이벤트 1건, `record_id` 유일).

## 실행

API 키 없이 전 경로가 돈다 (스텁 방식).

```bash
cd /Users/goorm/venv/d06

python3 tests/stub_run.py                            # 시나리오 9건
python3 tests/stub_run.py "연봉 정책 알려줘" employee   # 단일 질문 + 신원
python3 rag-agent/4-agent.py                         # 내장 데모 5건

python3 run_audit_engine.py audit-events/rag_audit_<YYYYMMDD>.jsonl   # 점검
python3 tests/tamper.py audit-events/rag_audit_<YYYYMMDD>.jsonl       # 변조 4종 생성
```

FastAPI 서버:

```bash
cd rag-agent && cp .env.example .env
RAG_PROVIDER=local python3 5-api.py                  # http://127.0.0.1:8000/docs
```

수동 테스트 절차·체크리스트 T-01~T-26 은 [TESTPLAN.md](TESTPLAN.md) 에 있다.

### 그 밖의 도구

```bash
python3 scan_pii.py            # 학습데이터·추론로그·피드백로그 개인정보 일괄 스캔
python3 run_audit_pipeline.py  # 엔드포인트 감사 이벤트 배치 파이프라인 (Aug31 엔진)
```

## 한계 — 배치 방식의 신뢰 공백

`jsonl` **적재 시점**과 **배치 실행 시점** 사이에 파일이 변조되면, 해시체인은 변조된
상태를 기준선으로 굳힌다. 해시체인이 지키는 것은 "체인이 만들어진 뒤의 변조"다.

이 공백을 없애려면 기록하는 순간 체인에 묶는 온라인 연동으로 가야 하고, 그러면
프로세스 재시작 시 마지막 해시 복원 로직과 워커 1개 제약이 붙는다. 배치가 자리잡은
뒤 별도로 판단할 일이다.
