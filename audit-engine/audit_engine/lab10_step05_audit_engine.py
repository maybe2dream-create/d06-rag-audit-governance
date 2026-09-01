"""
[Lab 10 - Step 5] 통합 감사 로그 엔진 (Integrated Audit Engine)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
plan.md B절 내용 구현 — Step 02/03/04 기능 통합:
  • Stage 1 (Step 02) 체인형 해시 결합 · 무결성 검증 · 위변조 탐지
  • Stage 2 (Step 03) 법정 보관 기간 · 근거 법률 · 만료 예정일 산출
  • Stage 3 (Step 04) PII 암호화 · DEK Key Vault · Crypto-Shredding 검증
  • Stage 4        3개 스테이지 결과 병합 통합 리포트 산출

■ 독립 동작 원칙 (plan.md B.3):
  기존 lab10_step01~04 모듈을 일절 import 하지 않으며, 전용 Config와 전용 출력 디렉터리
  (outputs/audit_engine/)를 사용하여 기존 실습 산출물을 침범하지 않습니다.

■ 사용 방법:
  $ python3 src/audit_engine/lab10_step05_audit_engine.py
  $ python3 src/audit_engine/lab10_step05_audit_engine.py <대상_감사로그_파일_경로>
  설정 변경: configs/lab10_audit_engine_config.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

# 스크립트 직접 실행(python3 src/audit_engine/lab10_step05_audit_engine.py)과
# 모듈 실행(python3 -m audit_engine.lab10_step05_audit_engine)을 모두 지원
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from audit_engine.config_loader import (
        AuditEngineConfigLoader, current_key_time_suffix, current_time_suffix,
        load_json, resolve_input_file, save_json, timestamped_path,
    )
    from audit_engine.checkpoints import CheckpointRecorder
    from audit_engine.crypto import AuditCryptoEngine, KeyVault, decrypt_with_key
    from audit_engine.hash_chain import AuditHashChain
    from audit_engine.models import parse_audit_events
    from audit_engine.retention import AuditRetentionEngine
else:
    from .config_loader import (
        AuditEngineConfigLoader, current_key_time_suffix, current_time_suffix,
        load_json, resolve_input_file, save_json, timestamped_path,
    )
    from .checkpoints import CheckpointRecorder
    from .crypto import AuditCryptoEngine, KeyVault, decrypt_with_key
    from .hash_chain import AuditHashChain
    from .models import parse_audit_events
    from .retention import AuditRetentionEngine

LINE = "=" * 88
SUB = "-" * 88


class IntegratedAuditEngine:
    """Step 02/03/04를 단일 파이프라인으로 통합 실행하는 오케스트레이터"""

    def __init__(self, base_dir: Path, config: dict, config_path: Path):
        self.base_dir = base_dir
        self.config = config
        self.config_path = config_path
        self.stages = config.get("pipeline_settings", {}).get("stages", {})
        self.out_settings = config.get("output_settings", {})
        self.time_suffix = current_time_suffix()
        # DEK 식별자에 결합할 실행 시각 (밀리초) — 재실행 시 Key Vault 덮어쓰기 방지
        self.key_time_suffix = current_key_time_suffix()
        pipe = config.get("pipeline_settings", {})
        self.cp = CheckpointRecorder(
            enabled=pipe.get("enable_checkpoints", True),
            verbose=pipe.get("verbose_checkpoints", True),
        )
        self.report: dict = {
            "engine": "lab10_step05_audit_engine",
            "generated_at": self.time_suffix,
            "key_time_suffix": self.key_time_suffix,
            "config_path": str(config_path),
            "stages": {},
        }

    # ------------------------------------------------------------------ Stage 0
    def load_events(self, cli_override: str | None = None):
        input_path = resolve_input_file(self.base_dir, self.config, cli_override)
        events = parse_audit_events(load_json(input_path))
        if not events:
            raise ValueError(f"감사 이벤트가 비어 있습니다: {input_path}")

        self.report["input"] = {"source_file": str(input_path), "event_count": len(events)}
        print(f"📂 [Stage 0] 대상 감사로그 로드 완료")
        print(f"   • 원본 파일 : {input_path}")
        print(f"   • 이벤트 수 : {len(events)}개")

        # ── CP-0: 입력 데이터가 파이프라인 진입 자격을 갖췄는지 ──
        field_names = events[0].field_names()
        complete = sum(1 for e in events if all(hasattr(e, f) for f in field_names))
        rids = [e.record_id for e in events]
        self.cp.record(
            "CP-0", "Stage 0", "입력 감사로그 로드 및 스키마 정규화",
            inputs={"source": input_path.name},
            outputs={"events": len(events), "unique_record_ids": len(set(rids))},
            invariants=[
                self.cp.inv("이벤트 1건 이상 로드", len(events) > 0, "> 0", f"{len(events)}건"),
                self.cp.inv("전 이벤트 5W1H 스키마 준수", complete == len(events),
                            f"{len(events)}건", f"{complete}건"),
                self.cp.inv("스키마 필드 수 일치", len(field_names) == 10, "10개", f"{len(field_names)}개"),
            ],
        )
        print()
        return events

    # ------------------------------------------------------------------ Stage 1
    def run_hash_chain(self, events) -> dict:
        print(SUB)
        print(" [Stage 1 / Step 02 통합] 체인형 해시 결합 및 위변조 탐지")
        print(SUB)

        if not self.stages.get("hash_chain", True):
            print("⏭️  Config 설정에 의해 건너뜁니다.\n")
            return {"skipped": True}

        rules = self.config.get("hash_chain_rules", {})
        algorithm = rules.get("hash_algorithm", "sha256")
        genesis = rules.get("genesis_previous_hash", "GENESIS")

        entries = AuditHashChain.build_chain(events, algorithm=algorithm, genesis_hash=genesis)
        print(f"🔗 체인 결합 완료: {len(entries)}개 엔트리 | 알고리즘: {algorithm.upper()}")
        print(f"   • 최초 previous_hash : {entries[0].previous_hash}")
        print(f"   • 최종 entry_hash    : {entries[-1].entry_hash[:48]}...")

        # ── CP-1: 결합 과정에서 이벤트 누락·증식·링크 단절이 없는지 ──
        links_ok = all(entries[i].previous_hash == entries[i - 1].entry_hash
                       for i in range(1, len(entries)))
        hlen = len(entries[0].entry_hash)
        expected_len = {"sha256": 64, "sha512": 128, "sha3_256": 64}.get(
            AuditHashChain.normalize_algorithm(algorithm), hlen)
        uniq_hashes = len({e.entry_hash for e in entries})
        self.cp.record(
            "CP-1", "Stage 1", "체인 해시 결합",
            inputs={"events": len(events), "algorithm": algorithm},
            outputs={"entries": len(entries), "unique_hashes": uniq_hashes},
            invariants=[
                self.cp.inv("엔트리 수 = 입력 이벤트 수", len(entries) == len(events),
                            f"{len(events)}개", f"{len(entries)}개"),
                self.cp.inv("최초 previous_hash = 제네시스",
                            entries[0].previous_hash == genesis, genesis, entries[0].previous_hash),
                self.cp.inv("인접 엔트리 링크 연속성", links_ok,
                            "전 구간 연결", "연결됨" if links_ok else "단절 발견"),
                self.cp.inv("해시 길이 = 알고리즘 규격", hlen == expected_len,
                            f"{expected_len}자", f"{hlen}자"),
                self.cp.inv("entry_hash 전건 고유", uniq_hashes == len(entries),
                            f"{len(entries)}종", f"{uniq_hashes}종"),
            ],
        )

        chain_path = timestamped_path(
            self.base_dir,
            self.out_settings.get("output_dir", "outputs/audit_engine"),
            self.out_settings.get("chain_filename", "audit_engine_chain.json"),
            self.time_suffix,
        )
        save_json([e.to_dict() for e in entries], chain_path)
        print(f"   💾 체인 산출물 저장 : {chain_path}")

        original = AuditHashChain.verify_chain(entries, algorithm=algorithm, genesis_hash=genesis)
        print(f"\n[검증 1] 원본 체인 무결성 : "
              f"{'✅ 성공 (Tamper-Proof 확인)' if original['valid'] else '❌ 실패'}")

        stage = {
            "skipped": False,
            "algorithm": original["algorithm"],
            "genesis_previous_hash": genesis,
            "entry_count": len(entries),
            "chain_file": str(chain_path),
            "original_verification": original,
        }

        pipeline = self.config.get("pipeline_settings", {})
        if pipeline.get("run_tamper_simulation", True):
            tampered_entries, meta = AuditHashChain.simulate_tampering(
                entries,
                target_index=int(pipeline.get("tamper_target_index", 1)),
                field_name=pipeline.get("tamper_field", "result"),
                new_value=pipeline.get("tamper_value", "tampered_success"),
            )
            print(f"\n[시뮬레이션] 엔트리 #{meta['tampered_entry_index']}의 "
                  f"'{meta['field']}' 필드 강제 변조 (해시는 미갱신)")
            print(f"   • 원본 값 : {meta['original_value']}")
            print(f"   • 변조 값 : {meta['tampered_value']}")

            tampered = AuditHashChain.verify_chain(
                tampered_entries, algorithm=algorithm, genesis_hash=genesis
            )
            detected = not tampered["valid"]
            print(f"[검증 2] 변조 후 체인 무결성 : "
                  f"{'🚨 변조 탐지 성공 (검증 실패 발생)' if detected else '❌ 변조 미탐지'}")
            for f in tampered["findings"]:
                print(f"   ↳ 엔트리 #{f['entry_index']} [{f['type']}] {f['detail']}")

            stage["tamper_simulation"] = {**meta, "verification": tampered, "detected": detected}

            # ── CP-2: 변조를 실제로 잡아내는지 (탐지 능력 자체를 검증) ──
            hit_idx = tampered["findings"][0]["entry_index"] if tampered["findings"] else None
            self.cp.record(
                "CP-2", "Stage 1", "위변조 주입 및 탐지",
                inputs={"tampered_index": meta["tampered_entry_index"], "field": meta["field"]},
                outputs={"detected": detected, "detected_index": hit_idx},
                invariants=[
                    self.cp.inv("변조 전 원본 체인은 유효", original["valid"], "valid", 
                                "valid" if original["valid"] else "invalid"),
                    self.cp.inv("변조 후 검증 실패(탐지)", detected, "탐지됨",
                                "탐지됨" if detected else "미탐지"),
                    self.cp.inv("탐지 위치 = 변조 위치",
                                hit_idx == meta["tampered_entry_index"],
                                f"#{meta['tampered_entry_index']}", f"#{hit_idx}"),
                ],
            )

        print()
        return stage

    # ------------------------------------------------------------------ Stage 2
    def run_retention(self, events) -> dict:
        print(SUB)
        print(" [Stage 2 / Step 03 통합] 법정 보관 기간 및 근거 법률 산출")
        print(SUB)

        if not self.stages.get("retention", True):
            print("⏭️  Config 설정에 의해 건너뜁니다.\n")
            return {"skipped": True}

        engine = AuditRetentionEngine(self.config.get("retention_settings", {}))
        results = engine.calculate_all(events)
        summary = AuditRetentionEngine.summarize(results)

        for idx, r in enumerate(results, start=1):
            flag = "" if r["timestamp_valid"] else "  ⚠️ 타임스탬프 파싱 실패"
            print(f"[{idx}] {r['action']:<20} | {r['retention_days']:>4}일 | "
                  f"만료 {r['retention_until']} | {r['legal_basis']}{flag}")

        # ── CP-3: 전 이벤트가 누락 없이 정책 산출되고 값이 물리적으로 타당한지 ──
        pos_days = sum(1 for r in results if r["retention_days"] > 0)
        # 만료일 비교는 파싱에 성공한 타임스탬프에만 적용한다.
        # 불량 타임스탬프(예: 'NOT_A_TIMESTAMP')를 날짜로 간주해 문자열 비교하면
        # 정상 동작인데도 실패로 판정되는 오탐이 발생한다.
        valid_rows = [r for r in results if r["timestamp_valid"]]
        future = sum(1 for r in valid_rows if r["retention_until"] >= r["event_timestamp"][:10])
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        invalid_rows = [r for r in results if not r["timestamp_valid"]]
        invalid_ok = sum(1 for r in invalid_rows if r["retention_until"] >= today)
        bucket_sum = summary["policy_matched"] + summary["default_policy_applied"]
        self.cp.record(
            "CP-3", "Stage 2", "보관기간·근거법률 산출",
            inputs={"events": len(events)},
            outputs={"results": len(results), "invalid_timestamp": summary["invalid_timestamp"]},
            invariants=[
                self.cp.inv("산출 건수 = 입력 이벤트 수", len(results) == len(events),
                            f"{len(events)}건", f"{len(results)}건"),
                self.cp.inv("전건 보관일수 > 0", pos_days == len(results),
                            f"{len(results)}건", f"{pos_days}건"),
                self.cp.inv("만료일 >= 이벤트 발생일 (유효 타임스탬프)",
                            future == len(valid_rows),
                            f"{len(valid_rows)}건", f"{future}건"),
                self.cp.inv("불량 타임스탬프는 현재시각 기준 산출",
                            invalid_ok == len(invalid_rows),
                            f"{len(invalid_rows)}건", f"{invalid_ok}건"),
                self.cp.inv("정책매칭 + 기본정책 = 전체", bucket_sum == len(results),
                            f"{len(results)}건", f"{bucket_sum}건"),
            ],
        )

        print(f"\n📊 요약: 정책 매칭 {summary['policy_matched']}건 / "
              f"기본정책 적용 {summary['default_policy_applied']}건 / "
              f"만료 도래 {summary['expired_records']}건 / "
              f"최장 보관 {summary['max_retention_days']}일\n")

        return {"skipped": False, "summary": summary, "results": results}

    # ------------------------------------------------------------------ Stage 3
    def run_crypto(self, events) -> dict:
        print(SUB)
        print(" [Stage 3 / Step 04 통합] PII 암호화 · Key Vault · Crypto-Shredding")
        print(SUB)

        if not self.stages.get("crypto", True):
            print("⏭️  Config 설정에 의해 건너뜁니다.\n")
            return {"skipped": True}

        vault_path = self.base_dir / self.out_settings.get(
            "key_vault_dir", "outputs/audit_engine/key_vault"
        ) / self.out_settings.get("key_vault_filename", "engine_key_vault.json")

        vault = KeyVault(vault_path)
        crypto = AuditCryptoEngine(self.config.get("crypto_rules", {}), vault,
                                   key_time_suffix=self.key_time_suffix)
        keys_before = vault.initial_key_count

        records = crypto.encrypt_events(events)
        verified_count = sum(1 for r in records if r["roundtrip_verified"])
        print(f"🔐 암호화 완료: {len(records)}개 레코드 | 대상 필드: {crypto.target_fields} | "
              f"키 길이: {crypto.key_size_bytes * 8}bit")
        print(f"   • 복호화 왕복 검증 성공: {verified_count}/{len(records)}건")

        print(f"   • DEK 키 접미사: @{crypto.key_time_suffix} "
              f"({'적용' if crypto.key_id_time_suffix else '미적용 — 재실행 시 키 충돌 위험'})")
        print(f"   • Vault 기존 키: {keys_before}개 → 신규 {len(records)}개 발급")

        sample = records[0]
        print(f"   • 샘플 Data ID : {sample['data_id']}")
        print(f"   • 샘플 암호문  : {sample['encrypted_payload']['ciphertext_b64'][:44]}...")

        # ── CP-4: 키가 소실·충돌 없이 보관되고 암호문에 평문이 남지 않았는지 ──
        data_ids = [r["data_id"] for r in records]
        in_vault = sum(1 for d in data_ids if d in vault)
        stamped = sum(1 for d in data_ids if d.endswith(f"@{crypto.key_time_suffix}"))
        pii_values = [getattr(ev, f, "") for ev in events for f in crypto.target_fields]
        pii_values = [v for v in pii_values if v and len(v) > 3]
        blob = json.dumps(records, ensure_ascii=False)
        leaked = [v for v in pii_values if v in blob]
        self.cp.record(
            "CP-4", "Stage 3", "PII 암호화 및 DEK 보관",
            inputs={"events": len(events), "pii_fields": ",".join(crypto.target_fields)},
            outputs={"records": len(records), "unique_data_ids": len(set(data_ids)),
                     "vault_keys_before": keys_before, "vault_keys_after": len(vault),
                     "overwritten_keys": len(vault.overwritten)},
            invariants=[
                self.cp.inv("레코드 수 = 입력 이벤트 수", len(records) == len(events),
                            f"{len(events)}건", f"{len(records)}건"),
                self.cp.inv("data_id 전건 고유 (키 충돌 없음)",
                            len(set(data_ids)) == len(data_ids),
                            f"{len(data_ids)}종", f"{len(set(data_ids))}종"),
                self.cp.inv("전 레코드 DEK가 Vault에 존재", in_vault == len(records),
                            f"{len(records)}건", f"{in_vault}건"),
                self.cp.inv("Vault 경유 복호화 왕복 전건 성공",
                            verified_count == len(records),
                            f"{len(records)}건", f"{verified_count}건"),
                self.cp.inv("산출물에 평문 PII 미포함", not leaked,
                            "0건", f"{len(leaked)}건"),
                # 실행 내 고유성만으로는 부족하다. 아래 3개는 '실행 간' 고유성을 검사한다.
                self.cp.inv("data_id에 실행 시각 접미사 결합", stamped == len(records),
                            f"{len(records)}건", f"{stamped}건"),
                self.cp.inv("기존 Vault 키 덮어쓰기 없음", not vault.overwritten,
                            "0건", f"{len(vault.overwritten)}건"),
                self.cp.inv("Vault 키 수 = 기존 + 신규 (누적 보존)",
                            len(vault) == keys_before + len(records),
                            f"{keys_before + len(records)}개", f"{len(vault)}개"),
            ],
        )

        shred_results = crypto.shred_records(records)
        if shred_results:
            print(f"\n🗑️  Crypto-Shredding 대상 action: {crypto.shred_target_actions}")
            for s in shred_results:
                print(f"   ↳ {s['data_id']} | 키 파기: {'✅' if s['key_removed'] else '❌'} | "
                      f"복호화 차단: {'✅ 차단됨' if s['decryption_blocked'] else '❌ 여전히 복호화 가능'}")
                if s["message"]:
                    print(f"      {s['message']}")
        else:
            print("\n🗑️  Crypto-Shredding 대상 레코드가 없습니다.")

        # ── CP-5: 파기 대상만 정확히 파기되고, 무관한 레코드는 온전한지 (과잉파기 방지) ──
        targets = [r for r in records if r["action"] in crypto.shred_target_actions]
        kept = [r for r in records if r["action"] not in crypto.shred_target_actions]
        gone = sum(1 for r in targets if r["data_id"] not in vault)
        blocked = sum(1 for s_ in shred_results if s_["decryption_blocked"])
        kept_ok = 0
        for r in kept:
            try:
                decrypt_with_key(r["encrypted_payload"], vault.get(r["data_id"]))
                kept_ok += 1
            except Exception:
                pass
        self.cp.record(
            "CP-5", "Stage 3", "Crypto-Shredding 파기 검증",
            inputs={"shred_targets": len(targets), "keep_records": len(kept)},
            outputs={"keys_removed": gone, "decryption_blocked": blocked},
            invariants=[
                self.cp.inv("파기 대상 DEK 전건 Vault에서 제거", gone == len(targets),
                            f"{len(targets)}건", f"{gone}건"),
                self.cp.inv("파기 대상 복호화 전건 차단", blocked == len(shred_results),
                            f"{len(shred_results)}건", f"{blocked}건"),
                self.cp.inv("비대상 레코드는 복호화 유지 (과잉파기 없음)",
                            kept_ok == len(kept), f"{len(kept)}건", f"{kept_ok}건"),
            ],
        )

        saved_vault = vault.save()
        enc_path = timestamped_path(
            self.base_dir,
            self.out_settings.get("output_dir", "outputs/audit_engine"),
            self.out_settings.get("encrypted_filename", "audit_engine_encrypted.json"),
            self.time_suffix,
        )
        save_json(records, enc_path)
        print(f"\n   💾 암호화 산출물 : {enc_path}")
        print(f"   🔑 Key Vault    : {saved_vault} (보관 키 {len(vault)}개)\n")

        return {
            "skipped": False,
            "algorithm": crypto.algorithm,
            "target_pii_fields": crypto.target_fields,
            "key_size_bits": crypto.key_size_bytes * 8,
            "encrypted_records": len(records),
            "roundtrip_verified": verified_count,
            "encrypted_file": str(enc_path),
            "key_vault_file": str(saved_vault),
            "keys_in_vault": len(vault),
            "key_time_suffix": crypto.key_time_suffix,
            "key_id_time_suffix_enabled": crypto.key_id_time_suffix,
            "vault_keys_before": keys_before,
            "overwritten_keys": len(vault.overwritten),
            "shred_target_actions": crypto.shred_target_actions,
            "shred_results": shred_results,
        }

    # ------------------------------------------------------------------ Stage 4
    def build_verdict(self) -> dict:
        """3개 스테이지 결과를 종합하여 최종 판정 산출"""
        chain = self.report["stages"].get("hash_chain", {})
        retention = self.report["stages"].get("retention", {})
        crypto = self.report["stages"].get("crypto", {})

        checks = {
            "chain_integrity_valid": chain.get("original_verification", {}).get("valid")
            if not chain.get("skipped") else None,
            "tamper_detected": chain.get("tamper_simulation", {}).get("detected")
            if not chain.get("skipped") else None,
            "retention_all_calculated": (
                retention.get("summary", {}).get("total_events", 0)
                == self.report["input"]["event_count"]
            ) if not retention.get("skipped") else None,
            "crypto_roundtrip_all_verified": (
                crypto.get("roundtrip_verified") == crypto.get("encrypted_records")
            ) if not crypto.get("skipped") else None,
            "shredded_decryption_blocked": (
                all(s["decryption_blocked"] for s in crypto.get("shred_results", []))
                if crypto.get("shred_results") else None
            ) if not crypto.get("skipped") else None,
        }

        evaluated = [v for v in checks.values() if v is not None]
        return {
            "checks": checks,
            "passed": sum(1 for v in evaluated if v),
            "evaluated": len(evaluated),
            "overall_pass": all(evaluated) if evaluated else False,
        }

    # ------------------------------------------------------------------ 실행
    def run(self, cli_override: str | None = None) -> dict:
        events = self.load_events(cli_override)

        self.report["stages"]["hash_chain"] = self.run_hash_chain(events)
        self.report["stages"]["retention"] = self.run_retention(events)
        self.report["stages"]["crypto"] = self.run_crypto(events)
        self.report["verdict"] = self.build_verdict()

        report_path = timestamped_path(
            self.base_dir,
            self.out_settings.get("output_dir", "outputs/audit_engine"),
            self.out_settings.get("report_filename", "audit_engine_report.json"),
            self.time_suffix,
        )
        save_json(self.report, report_path)
        self.report["report_file"] = str(report_path)

        # ── CP-6: 최종 산출물이 실제로 디스크에 온전히 기록되었는지 ──
        exists = report_path.exists()
        size = report_path.stat().st_size if exists else 0
        parsed, keys = False, []
        if exists:
            try:
                keys = list(load_json(report_path)["stages"].keys())
                parsed = True
            except Exception:
                parsed = False
        self.cp.record(
            "CP-6", "Stage 4", "통합 리포트 병합 및 영속화",
            inputs={"stages": len(self.report["stages"])},
            outputs={"file": report_path.name, "bytes": size},
            invariants=[
                self.cp.inv("리포트 파일 생성됨", exists, "존재", "존재" if exists else "없음"),
                self.cp.inv("JSON 재파싱 가능", parsed, "가능", "가능" if parsed else "불가"),
                self.cp.inv("3개 스테이지 키 보존", len(keys) == 3, "3개", f"{len(keys)}개"),
                self.cp.inv("verdict 판정 필드 존재", "verdict" in self.report,
                            "존재", "존재" if "verdict" in self.report else "없음"),
            ],
        )

        # 체크포인트 추적 기록을 리포트에 병합하고 별도 파일로도 저장
        self.report["checkpoints"] = self.cp.to_dict()
        if self.cp.enabled:
            trace_path = timestamped_path(
                self.base_dir,
                self.out_settings.get("output_dir", "outputs/audit_engine"),
                self.out_settings.get("checkpoint_filename", "audit_engine_checkpoints.json"),
                self.time_suffix,
            )
            save_json(self.report["checkpoints"], trace_path)
            self.report["checkpoint_file"] = str(trace_path)
            save_json(self.report, report_path)

        self.cp.print_summary(SUB)

        print()
        print(SUB)
        print(" [Stage 4] 통합 리포트 산출")
        print(SUB)
        verdict = self.report["verdict"]
        labels = {
            "chain_integrity_valid": "원본 체인 무결성 검증",
            "tamper_detected": "위변조 탐지 동작",
            "retention_all_calculated": "전체 이벤트 보관정책 산출",
            "crypto_roundtrip_all_verified": "암호화 복호화 왕복 검증",
            "shredded_decryption_blocked": "파기 후 복호화 차단",
        }
        for key, label in labels.items():
            value = verdict["checks"][key]
            mark = "⏭️  SKIP" if value is None else ("✅ PASS" if value else "❌ FAIL")
            print(f"   {mark}  {label}")

        print(f"\n   📄 통합 리포트 저장: {report_path}")
        if self.cp.enabled:
            cps = self.cp.summary()
            print(f"   🧭 체크포인트 추적: {self.report.get('checkpoint_file', '-')}")
            print(f"   🧭 중간 체크: {cps['passed']}/{cps['total']} 체크포인트 · "
                  f"{cps['invariants_passed']}/{cps['invariants_total']} 불변식 통과")
        print(f"   🏁 종합 판정: {verdict['passed']}/{verdict['evaluated']} 항목 통과 → "
              f"{'✅ 전체 통과' if verdict['overall_pass'] else '❌ 일부 실패'}")
        return self.report


def main() -> int:
    print(LINE)
    print(" [Lab 10 - Step 5] 통합 감사 로그 엔진 (Step 02 무결성 + Step 03 보관정책 + Step 04 암호화)")
    print(LINE)

    base_dir = Path(__file__).resolve().parent.parent.parent
    config_path = AuditEngineConfigLoader.default_config_path(base_dir)

    try:
        config = AuditEngineConfigLoader.load(config_path)
        print(f"⚙️  전용 Config 로드 성공: {config_path}\n")
    except Exception as exc:
        print(f"❌ Config 로드 실패: {exc}")
        return 1

    cli_override = sys.argv[1] if len(sys.argv) > 1 else None

    try:
        engine = IntegratedAuditEngine(base_dir, config, config_path)
        report = engine.run(cli_override)
    except Exception as exc:
        print(f"\n❌ 통합 엔진 실행 중 오류 발생: {type(exc).__name__}: {exc}")
        return 1

    print("\n✅ Lab 10 Step 5 완료: Step 02/03/04 통합 파이프라인 검증 성공.")
    return 0 if report["verdict"]["overall_pass"] else 2


if __name__ == "__main__":
    sys.exit(main())
