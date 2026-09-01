"""
[Lab 10 - Step 5 / audit_engine] Step 02 통합 - 체인형 해시 결합 및 위변조 탐지
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
plan.md B.4 Stage 1 내용 구현:
- previous_hash + 현재 이벤트를 정규화(canonical JSON) 결합하여 연쇄 해시 체인 형성
- Config로 해시 알고리즘(sha256/sha512/sha3_256) 및 제네시스 시드 해시 통제
- 검증 결과를 통합 리포트에 실을 수 있도록 구조화된 dict(findings 포함)로 반환
"""

from __future__ import annotations

import hashlib
import json

from .models import AuditEvent, AuditLogEntry

SUPPORTED_ALGORITHMS = {"sha256", "sha512", "sha3_256", "sha3_512", "sha384", "blake2b"}


class AuditHashChain:
    """Config 통제 기반 체인형 해시 생성 및 무결성 검증 엔진"""

    @staticmethod
    def canonical_json(data: dict) -> str:
        """키 정렬·공백 제거로 직렬화 순서에 따른 해시 변동을 제거"""
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def normalize_algorithm(algorithm: str) -> str:
        algo = (algorithm or "sha256").lower().replace("-", "_")
        return algo if algo in SUPPORTED_ALGORITHMS else "sha256"

    @classmethod
    def compute_hash(cls, event: AuditEvent, previous_hash: str, algorithm: str = "sha256") -> str:
        """Config에 설정된 해시 알고리즘으로 (이전 해시 + 현재 이벤트) 결합 해시 생성"""
        payload = {"event": event.to_dict(), "previous_hash": previous_hash}
        encoded = cls.canonical_json(payload).encode("utf-8")
        return hashlib.new(cls.normalize_algorithm(algorithm), encoded).hexdigest()

    @classmethod
    def build_chain(
        cls,
        events: list[AuditEvent],
        algorithm: str = "sha256",
        genesis_hash: str = "GENESIS",
    ) -> list[AuditLogEntry]:
        entries: list[AuditLogEntry] = []
        previous_hash = genesis_hash

        for event in events:
            entry_hash = cls.compute_hash(event, previous_hash, algorithm)
            entries.append(AuditLogEntry(event=event, previous_hash=previous_hash, entry_hash=entry_hash))
            previous_hash = entry_hash

        return entries

    @classmethod
    def verify_chain(
        cls,
        entries: list[AuditLogEntry],
        algorithm: str = "sha256",
        genesis_hash: str = "GENESIS",
    ) -> dict:
        """체인 전체를 검증하고 {valid, checked, findings} 구조로 결과 반환"""
        expected_previous = genesis_hash
        findings: list[dict] = []
        checked = 0

        for idx, entry in enumerate(entries, start=1):
            checked = idx

            if entry.previous_hash != expected_previous:
                findings.append({
                    "entry_index": idx,
                    "type": "broken_link",
                    "detail": "이전 해시 링크가 끊어져 체인 연속성이 파괴되었습니다.",
                    "expected_previous_hash": expected_previous[:32],
                    "actual_previous_hash": entry.previous_hash[:32],
                    "actor": entry.event.actor,
                    "action": entry.event.action,
                })
                break

            recomputed = cls.compute_hash(entry.event, entry.previous_hash, algorithm)
            if entry.entry_hash != recomputed:
                findings.append({
                    "entry_index": idx,
                    "type": "tampered_payload",
                    "detail": "기록된 해시와 재계산 해시가 불일치하여 데이터 위변조가 감지되었습니다.",
                    "recorded_hash": entry.entry_hash[:32],
                    "recomputed_hash": recomputed[:32],
                    "actor": entry.event.actor,
                    "action": entry.event.action,
                    "result": entry.event.result,
                })
                break

            expected_previous = entry.entry_hash

        return {
            "algorithm": cls.normalize_algorithm(algorithm),
            "genesis_previous_hash": genesis_hash,
            "total_entries": len(entries),
            "checked_entries": checked,
            "valid": len(findings) == 0,
            "findings": findings,
        }

    @classmethod
    def simulate_tampering(
        cls,
        entries: list[AuditLogEntry],
        target_index: int,
        field_name: str,
        new_value: str,
    ) -> tuple[list[AuditLogEntry], dict]:
        """엔트리 데이터만 변조하고 해시는 그대로 둔 사본을 만들어 탐지 능력을 검증"""
        if not entries:
            raise ValueError("변조 시뮬레이션을 수행할 체인 엔트리가 없습니다.")

        idx = max(0, min(target_index, len(entries) - 1))
        tampered = list(entries)
        original_entry = tampered[idx]
        original_value = getattr(original_entry.event, field_name)

        tampered[idx] = AuditLogEntry(
            event=original_entry.event.replace_field(field_name, new_value),
            previous_hash=original_entry.previous_hash,
            entry_hash=original_entry.entry_hash,  # 해시는 갱신하지 않음 (공격자 시나리오)
        )

        meta = {
            "tampered_entry_index": idx + 1,
            "field": field_name,
            "original_value": original_value,
            "tampered_value": new_value,
            "unchanged_entry_hash": original_entry.entry_hash[:32],
        }
        return tampered, meta
