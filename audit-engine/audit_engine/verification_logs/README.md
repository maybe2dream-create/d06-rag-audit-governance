# audit_engine 파이프라인 검증용 감사로그 (verification_logs)

통합 감사 엔진 `src/audit_engine/lab10_step05_audit_engine.py`의 **파이프라인 분기를
빠짐없이 자극하기 위한 고정 검증 데이터셋**입니다.

- **생성기**: `src/lab10_step01_schema_generator.py`의 `AuditDummyGenerator` (Step 01 코드 재사용)
- **생성 드라이버**: `src/lab10_gen_verification_logs.py`
- **데이터셋 정의**: `configs/lab10_verification_generator_config.json`
- **재생성 명령**: `python3 src/lab10_gen_verification_logs.py`

> 검증 재현성을 위해 타임스탬프 접미사 없는 **고정 파일명**으로 저장됩니다.
> 이 디렉터리에는 데이터(JSON)만 존재하며 `audit_engine` 패키지의 코드 독립성에 영향을 주지 않습니다.

## 데이터셋 구성

| 파일 | 건수 | 자극 대상 분기 |
|---|---:|---|
| `verify_01_baseline_normal.json` | 9 | 전 스테이지 기준선 (정상 4 + 5대 취약점 5) |
| `verify_02_single_event.json` | 1 | 체인 길이 1 경계값, 변조 인덱스 클램핑 |
| `verify_03_unknown_action.json` | 4 | Stage 2 `default_policy` 폴백 |
| `verify_04_no_shred_target.json` | 3 | Stage 3 파기 대상 없음 → 검증 항목 SKIP |
| `verify_05_multi_shred.json` | 6 | Stage 3 다중 DEK 파기 |
| `verify_06_malformed_timestamp.json` | 5 | Stage 2 타임스탬프 파싱 예외 폴백 |
| `verify_07_bulk_volume.json` | 30 | 처리량 + `record_id` 중복 내성 |
| `manifest.json` | — | 각 파일의 목적·기대결과·통계 메타데이터 |

## 사용 방법

```bash
# 개별 검증
python3 src/audit_engine/lab10_step05_audit_engine.py src/audit_engine/verification_logs/verify_01_baseline_normal.json

# 전체 일괄 검증
for f in src/audit_engine/verification_logs/verify_*.json; do
  python3 src/audit_engine/lab10_step05_audit_engine.py "$f" | grep "종합 판정"
done
```

## 참고

- `verify_06`의 불량 타임스탬프는 Step 01 생성기가 `timestamp`를 현재시각으로 고정 부여하므로
  **생성 후 주입**됩니다 (주입 내역은 `manifest.json`의 `injected_timestamp_overrides` 참조).
- `verify_07`은 시나리오 순환 생성 특성상 `record_id`가 25건 중복됩니다. 이는 의도된 설계로,
  DEK 키 충돌 내성을 검증하기 위한 것입니다.
