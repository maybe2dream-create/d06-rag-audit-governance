# audit-sdk

5W1H 감사 기록 SDK. 앱은 이 패키지를 **쓰기만** 하면 된다.

감사 로그의 필드 계약, append-only 적재, 요청 컨텍스트, 거부 요청 자동 기록이 모두
안에 들어 있다. 서비스마다 손으로 맞추면 포맷이 갈라지고 결국 한 파이프라인으로
처리할 수 없게 된다.

## 설치

```bash
pip install -e audit-sdk          # 정식 설치
```

설치하지 않아도 된다. `rag-agent/core/audit_setup.py`와 `run_audit_pipeline.py`는
형제 폴더에서 SDK를 찾는 경로 부트스트랩을 갖고 있다.

의존성은 **표준 라이브러리뿐**이다. FastAPI는 `audit_sdk.integrations.fastapi`를
쓸 때만 필요하고, 그것도 타입 힌트로만 참조해 import 하지 않는다.

## 쓰는 법

```python
from audit_sdk import AuditClient
from audit_sdk.integrations.fastapi import install_audit

audit = AuditClient(service="rag-service", out_dir=BASE_DIR / "audit_out")
install_audit(app, audit)     # 미들웨어 + 401/403/422/429/5xx 자동 기록

# 엔드포인트에서
audit.record(action="rag_query", asset="vector_index",
             result="success", user=current_user, purpose=question)

# 인증 관문에서
audit.set_actor(username, role)

# 인증 전, 시도한 계정을 남겨야 할 때 (로그인 rate limit)
audit.set_actor_hint(username)
```

배치 처리:

```python
from audit_sdk.pipeline import run_batch
result = run_batch(audit, engine_dir, rotate=True)
```

## 구조

| 모듈 | 역할 | 엔진 의존 |
|---|---|---|
| `event.py` | 5W1H 필드 계약, 이벤트 빌더 | 없음 |
| `context.py` | 요청 컨텍스트 (ContextVar) | 없음 |
| `sink.py` | `JsonlSink`(append-only) / `MemorySink`(테스트) | 없음 |
| `client.py` | `AuditClient` — record / set_actor / rotate | 없음 |
| `integrations/fastapi.py` | `install_audit(app, client)` | 없음 |
| `pipeline.py` | 감사엔진 배치 호출 | **있음** |

**코어는 감사엔진을 import 하지 않는다.** 엔진을 부르는 것은 `pipeline`뿐이고 배치
실행 쪽에서만 import 한다. 감사 대상(앱)이 감사 도구(엔진)의 코드를 재사용하면 같은
버그를 공유해 결함을 놓친다.

## SDK가 대신 밟아주는 함정 두 가지

**1. threadpool ContextVar** — FastAPI는 동기 핸들러와 의존성을 threadpool에서
실행하며 컨텍스트를 복사한다. 복사본에서 `ContextVar.set()`을 부르면 미들웨어가 보는
원본에 반영되지 않는다. `context.py`는 dict를 제자리에서 수정해 이 문제를 피한다.
이걸 모르면 500 오류의 actor가 조용히 `UNKNOWN_ANONYMOUS`로 남는다.

**2. 요청당 감사 이벤트 1건** — `require_login` 같은 의존성이 거부한 요청은 핸들러
본문에 들어오지 않으므로 미들웨어가 대신 기록해야 한다. 그런데 핸들러가 이미 기록한
요청(로그인 실패 등)까지 미들웨어가 또 남기면 같은 `record_id`가 두 번 등장해
추적성이 훼손된다. `client.record()`가 표시를 남기고 미들웨어가 건너뛴다.

## Python 3.9 호환

`X | Y` 유니온과 `list[str]` 빌트인 제네릭을 런타임에 쓰지 않는다.
모든 모듈에 `from __future__ import annotations`가 들어 있다.
