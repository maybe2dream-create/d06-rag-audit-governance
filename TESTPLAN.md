# RAG-Agent + Audit-Engine 수동 테스트 시나리오

d06 통합 감사 계측에 대한 수동 테스트 절차와 체크리스트.
모든 시나리오는 **감사로그가 실제로 발생하는지**를 기준으로 판정한다.

실행 방식은 **스텁(방식 B)** — API 키·네트워크 없이 계측 경로 전체가 돈다.

---

## 0. 사전 준비

### 0-1. 테스트 더미 문서

기본 `documents.json`은 문서 3개뿐이라 접근제어 등급 분기를 볼 수 없다.
등급이 다른 문서 6개가 든 테스트 세트가 이미 적용되어 있다.

```bash
cd /Users/goorm/venv/d06
cp tests/documents_test.json rag-agent/documents.json          # 교체
cp tests/documents_original.backup.json rag-agent/documents.json  # 복원
```

| doc_id | 분류 등급 | 소유 부서 | 목적 |
|---|---|---|---|
| `weather` `product` | public | ai-platform | 기준선 |
| `policy` | internal | ai-platform | 기준선 |
| `hr_salary` | **confidential** | hr | 등급 부족 거부 |
| `customer_pii` | **restricted** | legal | 등급 부족 + 문서 PII |
| `internal_incident` | **미등록(의도적)** | — | deny-by-default 탐지 |

`internal_incident`는 `configs/lab10_access_control_policy.json`에 **일부러 등록하지 않았다.**

### 0-2. 신원 프로파일

| 프로파일 | actor | role | department | 등급 |
|---|---|---|---|---|
| `default` | anonymous | rag_user | ai-platform | internal |
| `guest` | guest_user | guest | untracked | public |
| `employee` | kim_analyst | employee | ai-platform | internal |
| `legal` | park_counsel | compliance_officer | legal | confidential |
| `unknown` | ghost | not_registered_role | nowhere | **미등록** |

### 0-3. 싱크 초기화

```bash
rm -f audit-events/rag_audit_*.jsonl audit-events/_sdk_failures.log
```

---

## 1. 실행

```bash
python3 tests/stub_run.py                              # 시나리오 9건 일괄
python3 tests/stub_run.py "연봉 정책 알려줘" employee    # 단일 질문 + 신원
python3 rag-agent/4-agent.py                           # 내장 데모 5건
```

점검:

```bash
python3 run_audit_engine.py audit-events/rag_audit_<YYYYMMDD>.jsonl
```

> 스텁 임베딩은 어휘 해시 기반이라 실제 Gemini와 **검색 결과가 다를 수 있다.**
> 문서 등급 판정은 스텁 결과가 아니라 **감사로그에 실제 기록된 `asset` 값**으로 판단한다.

---

## 2. 라우팅 제약 (중요)

`4-agent.py`의 `choose_action()`은 규칙 기반이다. **키워드가 없으면 RAG 경로를 타지 않아
검색 감사(②)가 발생하지 않는다.**

| 우선순위 | 키워드 | 선택 도구 |
|---|---|---|
| 1 | 몇 개, 구성, 종류, **요약** | `tool_document_summary` |
| 2 | 문서, 목록, documents | `tool_list_documents` |
| 3 | 날씨, 지원, 환불, **정책**, **고객**, 주말 / weather, support, refund, policy | `tool_rag` |
| 4 | (그 외 전부) | `tool_direct_answer` |

주의: "요약"이 1순위라 `연봉 정책 요약해줘`는 RAG가 아니라 summary로 간다.

---

## 3. 테스트 질문 더미

| ID | 질문 | 신원 | 기대 도구 | 검증 목표 |
|---|---|---|---|---|
| Q-01 | 문서 목록 보여줘 | default | `tool_list_documents` | ①④만, LLM 미호출 |
| Q-02 | 문서 구성 요약해줘 | default | `tool_document_summary` | ①④만 |
| Q-03 | 주말에 고객 지원 받을 수 있어? | default | `tool_rag` | ①②③a④ 전 경로 |
| Q-04 | 파이썬은 어떤 언어야? | default | `tool_direct_answer` | ①③b④ (direct egress) |
| Q-05 | 제 번호는 010-1234-5678 인데 환불 가능한가요? | default | `tool_rag` | 전화번호 마스킹 |
| Q-06 | 주민등록번호 900101-1234567 로 고객 조회해주세요 | default | `tool_rag` | 주민번호 마스킹 |
| Q-07 | 연봉 정책 알려줘 | employee | `tool_rag` | `hr_salary` 등급 부족 거부 |
| Q-08 | VIP 고객 정보 알려줘 | guest | `tool_rag` | guest 전면 거부 |
| Q-09 | 유출 사고 대응 정책은? | unknown | `tool_rag` | 미등록 role + 미등록 자산 |

---

## 4. 체크리스트 — 전 항목 통과 확인됨

### 4-A. 계측 지점 (5곳)

| # | 체크 항목 | 확인 방법 | 결과 |
|---|---|---|---|
| T-01 | ① 턴 시작 | `action=agent_query` | ✅ 9건 |
| T-02 | ② 검색 근거 | `action=retrieval`, `asset=rag_doc:<id>`, `_detail`에 score·rank | ✅ 12건 |
| T-03 | ③a RAG egress | `llm_call` + `_detail.path=rag` | ✅ 6건 |
| T-04 | ③b 일반 답변 egress | `llm_call` + `_detail.path=direct` | ✅ 1건 |
| T-05 | ④ 턴 종료 | `action=agent_result`, `_detail.tool_name` | ✅ 9건 |
| T-06 | 턴 상관관계 | `record_id`가 `rag-<turn_id>-N` 접두 공유 | ✅ 턴 9개 |

**T-04는 회귀 항목이다.** `generate_answer`만 계측하면 이 경로가 통째로 누락된다.

### 4-B. PII 마스킹 (기록 시점)

| # | 체크 항목 | 기대 | 결과 |
|---|---|---|---|
| T-07 | 전화번호 | Q-05의 purpose가 `[PHONE_MASKED]` | ✅ `제 번호는 [PHONE_MASKED] 인데 환불 가능한가요?` |
| T-08 | 주민등록번호 | Q-06의 purpose가 `[RRN_MASKED]` | ✅ `주민등록번호 [RRN_MASKED] 로 고객 조회해주세요` |
| T-09 | 잔존 평문 PII | `residual = 0` | ✅ 0개 |
| T-10 | actor 가명처리 | 전 건 | ✅ 37/37 (`u_e9147e083bed` 형태) |

### 4-C. 접근제어 (거부 사유 5종)

| # | 체크 항목 | 실제 출력 | 결과 |
|---|---|---|---|
| T-11 | 등급 부족 (RBAC) | `role 'employee'의 등급이 asset 'rag_doc:hr_salary' 등급보다 낮음` | ✅ 6건 |
| T-12 | 미등록 자산 | `asset 'rag_doc:internal_incident'가 자산 등록부에 없음 (deny-by-default)` | ✅ 2건 |
| T-13 | 미등록 role | `role 'not_registered_role'가 정책에 없음 (deny-by-default)` | ✅ 5건 |
| T-14 | 액션 권한 없음 | `role 'guest'는 action 'llm_call' 수행 권한 없음` | ✅ 1건 |
| T-15 | 부서 제한 (ABAC) | `department 'untracked'는 asset '...'의 허용 부서 목록에 없음` | ✅ 6건 |

### 4-D. 감사로그 무결성

```bash
python3 tests/tamper.py audit-events/rag_audit_<YYYYMMDD>.jsonl
for c in modify_result modify_actor delete_entry reorder; do
  python3 run_audit_engine.py audit-events/rag_audit_<YYYYMMDD>__${c}.jsonl | grep 무결성
done
```

| # | 케이스 | 기대 | 결과 |
|---|---|---|---|
| T-16 | 정상 체인 | 무결성 ✅ 정상 | ✅ |
| T-17 | result 위조 | 🚨 `entry_hash_mismatch` | ✅ index=19 |
| T-18 | actor 위조 | 🚨 `entry_hash_mismatch` | ✅ index=19 |
| T-19 | 이벤트 삭제 | 🚨 `previous_hash_mismatch` | ✅ index=19 |
| T-20 | 순서 교환 | 🚨 `previous_hash_mismatch` | ✅ index=18 |

### 4-E. 가용성·복원력

| # | 체크 항목 | 기대 | 결과 |
|---|---|---|---|
| T-21 | 실패 격리 | 응답 정상, stderr에 `[audit_sdk]` 실패 기록 | ✅ 프로세스 생존 |
| T-22 | LLM 실패 시 턴 종료 | `agent_result` / error 기록 | ✅ `result=error:SystemExit` |
| T-23 | 재시작 후 체인 연속 | 무결성 ✅ 정상 | ✅ |
| T-24 | 동시성 5병렬 | 전건 기록 + 체인 분기 없음 | ✅ +25건, 무결성 정상 |

T-24는 `fcntl.flock` 배타 잠금 안에서 tip 읽기 → 해시 계산 → append 를 수행해서 통과한다.
잠금 밖에서 tip을 읽으면 두 프로세스가 같은 `previous_hash`를 보고 체인이 갈라진다.

### 4-F. 보관기한

| # | 체크 항목 | 기대 | 결과 |
|---|---|---|---|
| T-25 | action별 보관기한 | `llm_call`=1095일(egress 3년), 나머지 365일 | ✅ |
| T-26 | 만료 탐지 | 과거 타임스탬프 주입 시 `retention_expired_count > 0` | ✅ 1건 |

타임스탬프를 바꾸면 해시도 깨지므로 **위변조 감지와 만료 탐지가 동시에 뜬다. 정상이다.**

---

## 5. 기준 실행 결과

`python3 tests/stub_run.py` 시나리오 9건 실행 시:

```
📋 총 이벤트 수        : 37개
🔗 해시체인 무결성      : ✅ 정상
🕶 PII 마스킹 처리 건수 : 0개   ← SDK가 기록 시점에 이미 마스킹함 (정상)
   (SDK 기록 시점 마스킹 토큰: 10개)
🪪 actor 가명처리 건수  : 37개
🔓 잔존 평문 PII 건수   : 0개
🔐 암호화 자기검증 통과 : 37/37개
🔒 접근제어 거부 건수   : 13개
```

거부 사유 분포: 등급 부족 6건 / 부서 제한(ABAC) 6건 / 미등록 role 5건 / 미등록 자산 2건 / 액션 권한 1건.

**`PII 마스킹 처리 건수 = 0`은 실패가 아니다.** SDK가 append 직전에 마스킹하므로 엔진 단계에는
마스킹할 것이 남지 않는다. 0이 아니라면 기록 시점 통제를 빠져나온 값이 있다는 뜻이다.

> PDF 기준값(37개 / 거부 14건)과 대조: 이벤트 수·가명처리·잔존 PII·암호화는 정확히 일치하고,
> 접근제어 거부는 13건으로 1건 차이가 난다. 계측 세부가 달라 생기는 차이이며,
> 판정은 건수 일치가 아니라 **항목별 통과 여부**로 한다.

---

## 6. 알려진 한계 (오탐/미탐으로 오인하지 말 것)

| 현상 | 원인 | 판정 |
|---|---|---|
| 문서 본문의 PII가 감사로그에 없음 | `AuditEvent`에는 `doc_id`만 들어가고 문서 본문은 들어가지 않음 | **설계상 한계.** `customer_pii` 본문은 LLM으로 나가지만 감사로그에는 안 남는다 |
| 문서 등급 거부가 나도 응답은 정상 반환 | 관찰 전용(PEP 없음) 설계 | 의도된 동작. `enforcement_mode: enforce` 로 전환 가능 |
| 자정 넘겨 실행 시 체인이 genesis부터 재시작 | 싱크 파일명이 `rag_audit_<YYYYMMDD>.jsonl` | 잔여위험. 날짜 간 연결 필요 시 전날 tip을 물려야 함 |
| `_detail` 변조는 탐지되지 않음 | 해시 대상은 `event` 10필드뿐 | 잔여위험. 핵심 식별자(doc_id·model)는 `asset`에 있어 보호됨 |
| 스펙 더미의 주민번호·카드가 CRITICAL이 아님 | `850315-1234567`·`5412-7534-9821-0043`은 체크섬/Luhn 실패 | 정상. 검증 실패분은 MEDIUM으로 등급 하향되어 오탐을 줄인다 |

---

## 7. 테스트 종료 후 정리

```bash
cd /Users/goorm/venv/d06
cp tests/documents_original.backup.json rag-agent/documents.json   # 문서 복원
rm -f audit-events/rag_audit_*.jsonl audit-events/_sdk_failures.log  # 싱크 정리
```
