"""
[Lab 10 - Step 5 / audit_engine] Step 04 통합 - 민감정보 암호화 · Key Vault · Crypto-Shredding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
plan.md B.4 Stage 3 내용 구현:
- 레코드별 DEK(Data Encryption Key) 발급 후 SHA-256 키스트림 XOR 스트림 암호화
- 암호화 대상 PII 필드(actor/purpose 등)를 Config로 통제
- DEK를 본문과 분리하여 전용 Key Vault 파일에 보관, Vault 조회 기반 복호화 검증
- 파기 대상 DEK 삭제(Crypto-Shredding) 후 복호화가 차단되는지 검증
- DEK 식별자(data_id)에 실행 시각을 결합하여 재실행 시 기존 키가 덮어써지지 않도록 보장
"""

from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets

from .models import AuditEvent


class KeyNotFoundError(Exception):
    """DEK가 파기(Crypto-Shredded)되었거나 Key Vault에 없을 때 발생"""


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """SHA-256(key || nonce || counter) 블록을 이어붙여 키스트림 생성"""
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def encrypt_data(plaintext: str, key: bytes) -> dict:
    """평문을 DEK로 스트림 암호화하여 nonce/ciphertext(Base64) 반환"""
    nonce = secrets.token_bytes(16)
    raw = plaintext.encode("utf-8")
    ks = keystream(key, nonce, len(raw))
    ciphertext = bytes(a ^ b for a, b in zip(raw, ks))
    return {
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_with_key(payload: dict, key: bytes) -> str:
    """DEK가 주어졌을 때 암호문을 복호화"""
    nonce = base64.b64decode(payload["nonce_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    ks = keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks)).decode("utf-8")


class KeyVault:
    """DEK 데이터 키 저장소 (암호문과 물리적으로 분리 보관)"""

    def __init__(self, vault_path: str | Path):
        self.vault_path = Path(vault_path)
        self._keys: dict[str, str] = {}
        if self.vault_path.exists():
            with open(self.vault_path, "r", encoding="utf-8") as f:
                self._keys = json.load(f)
        # Vault는 실행할 때마다 누적되므로, 이번 실행이 기존 키를 덮어썼는지 판별하려면
        # 적재 시점의 키 개수와 덮어쓰기 발생 이력을 따로 들고 있어야 한다.
        self.initial_key_count: int = len(self._keys)
        self.overwritten: list[str] = []

    def put(self, data_id: str, dek: bytes) -> None:
        # 이미 존재하는 data_id에 새 DEK를 쓰면 앞선 암호문은 영구 복호화 불가가 된다.
        # 조용히 덮어쓰지 않고 이력을 남겨 CP-4 불변식이 즉시 잡아내도록 한다.
        if data_id in self._keys:
            self.overwritten.append(data_id)
        self._keys[data_id] = base64.b64encode(dek).decode("utf-8")

    def get(self, data_id: str) -> bytes:
        if data_id not in self._keys:
            raise KeyNotFoundError(
                f"[Crypto-Shredded] 데이터 키 '{data_id}'가 Key Vault에 없어 복호화가 불가능합니다."
            )
        return base64.b64decode(self._keys[data_id])

    def shred(self, data_id: str) -> bool:
        """DEK를 영구 삭제하여 대응 암호문을 복구 불가능 상태로 전환"""
        return self._keys.pop(data_id, None) is not None

    def __contains__(self, data_id: str) -> bool:
        return data_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def save(self) -> Path:
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(self._keys, f, indent=4, ensure_ascii=False)
        return self.vault_path


class AuditCryptoEngine:
    """Config 통제 기반 감사로그 PII 암호화 및 Crypto-Shredding 엔진"""

    def __init__(self, crypto_rules: dict | None, vault: KeyVault,
                 key_time_suffix: str | None = None):
        rules = crypto_rules or {}
        self.target_fields: list[str] = rules.get("target_pii_fields", ["actor", "purpose"])
        self.key_size_bytes: int = max(16, int(rules.get("key_size_bits", 256)) // 8)
        self.algorithm: str = rules.get("algorithm", "sha256-keystream-xor")
        self.shred_target_actions: list[str] = rules.get("shred_target_actions", [])
        self.verify_decryption: bool = rules.get("verify_decryption", True)
        # Config 통제: data_id 뒤에 실행 시각을 붙일지 여부 (기본 ON)
        self.key_id_time_suffix: bool = rules.get("key_id_time_suffix", True)
        self.key_time_suffix: str = key_time_suffix or datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f")[:-3]
        self.vault = vault

    def build_data_id(self, event: AuditEvent, idx: int) -> str:
        """DEK 식별자 생성 — record_id + 실행 내 순번 + 실행 시각(밀리초)

        record_id는 시나리오 순환 생성 시 중복될 수 있어 순번을 결합하고(실행 내 고유),
        순번까지 같은 값은 재실행 때마다 반복되므로 실행 시각을 덧붙인다(실행 간 고유).
        시각 접미사가 없으면 두 번째 실행이 첫 실행의 DEK를 Key Vault에서 덮어써
        먼저 만든 암호문이 영구 복호화 불가 상태가 된다.
        """
        base_id = f"{event.record_id or 'rec'}#{idx:04d}:pii"
        if not self.key_id_time_suffix:
            return base_id
        return f"{base_id}@{self.key_time_suffix}"

    def build_plaintext(self, event: AuditEvent) -> str:
        """Config가 지정한 PII 필드만 골라 암호화 대상 평문 구성"""
        parts = []
        for field_name in self.target_fields:
            parts.append(f"{field_name}={getattr(event, field_name, '')}")
        return " | ".join(parts)

    def encrypt_events(self, events: list[AuditEvent]) -> list[dict]:
        """이벤트별 DEK 발급 → PII 암호화 → Vault 저장. 원문은 반환값에 남기지 않음"""
        records: list[dict] = []

        for idx, ev in enumerate(events, start=1):
            data_id = self.build_data_id(ev, idx)
            dek = secrets.token_bytes(self.key_size_bytes)
            plaintext = self.build_plaintext(ev)

            payload = encrypt_data(plaintext, dek)
            payload["data_id"] = data_id
            self.vault.put(data_id, dek)

            # 왕복 검증은 반드시 Key Vault를 경유해야 키 저장 누락·충돌까지 탐지할 수 있다
            verified = None
            if self.verify_decryption:
                try:
                    verified = decrypt_with_key(payload, self.vault.get(data_id)) == plaintext
                except KeyNotFoundError:
                    verified = False

            records.append({
                "index": idx,
                "data_id": data_id,
                "key_issued_at": self.key_time_suffix if self.key_id_time_suffix else None,
                "event_summary": f"[{ev.action}] {ev.asset}",
                "action": ev.action,
                "encrypted_fields": list(self.target_fields),
                "algorithm": self.algorithm,
                "key_size_bits": self.key_size_bytes * 8,
                "encrypted_payload": payload,
                "roundtrip_verified": verified,
                "shredded": False,
            })

        return records

    def shred_records(self, records: list[dict]) -> list[dict]:
        """Config 지정 action에 해당하는 레코드의 DEK를 Vault에서 파기하고 결과 검증"""
        shred_results: list[dict] = []

        for rec in records:
            if rec["action"] not in self.shred_target_actions:
                continue

            data_id = rec["data_id"]
            removed = self.vault.shred(data_id)
            rec["shredded"] = removed

            # 파기 후 실제로 복호화가 차단되는지 확인
            blocked, message = False, ""
            try:
                decrypt_with_key(rec["encrypted_payload"], self.vault.get(data_id))
            except KeyNotFoundError as exc:
                blocked, message = True, str(exc)

            shred_results.append({
                "data_id": data_id,
                "action": rec["action"],
                "key_removed": removed,
                "decryption_blocked": blocked,
                "message": message,
            })

        return shred_results
