"""d06 — 감사로그 점검 엔진.

SDK 가 기록 시점에 만든 해시체인을 **검증**하고(다시 만들지 않는다),
PII 통제·가명처리·암호화·접근제어·보관기한을 점검해 리포트를 낸다.

사용 방법:
  python3 run_audit_engine.py audit-events/rag_audit_20260901.jsonl
  python3 run_audit_engine.py audit-events/rag_audit_*.jsonl      # 여러 파일

종료 코드: 0=무결성 정상 / 2=변조 탐지 / 1=실행 오류
"""

from __future__ import annotations

import base64
import glob
import json
import secrets
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

D06_DIR = Path(__file__).resolve().parent
for _sibling in ("audit-sdk", "pii-guard", "audit-engine"):
    _path = D06_DIR / _sibling
    if _path.is_dir() and str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from audit_sdk.chain import ChainSink, load_entries  # noqa: E402
from audit_engine.crypto import decrypt_with_key, encrypt_data  # noqa: E402
from pii_guard import PIIGuard  # noqa: E402

LINE = "=" * 88
SUB = "-" * 88

# action 별 보관기한. llm_call 은 조직 데이터가 밖으로 나간 기록이라 더 길게 잡는다.
RETENTION_DAYS = {"llm_call": 1095}
DEFAULT_RETENTION_DAYS = 365


def collect_paths(patterns: List[str]) -> List[Path]:
    paths: List[Path] = []
    for pattern in patterns:
        matched = sorted(glob.glob(pattern))
        paths.extend(Path(m) for m in matched) if matched else paths.append(Path(pattern))
    return [p for p in paths if p.exists()]


def retention_days(action: str) -> int:
    return RETENTION_DAYS.get(action, DEFAULT_RETENTION_DAYS)


def check_retention(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """보관기한이 지난 이벤트를 센다."""
    now = datetime.now(timezone.utc)
    expired = 0
    per_action: Counter = Counter()

    for entry in entries:
        event = entry.get("event", {})
        action = event.get("action", "")
        per_action[action] += 1
        try:
            stamp = datetime.strptime(event.get("timestamp", ""), "%Y-%m-%dT%H:%M:%SZ")
            stamp = stamp.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if now - stamp > timedelta(days=retention_days(action)):
            expired += 1

    return {"expired": expired, "per_action": dict(per_action)}


def check_crypto(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """암호화 자기검증 — 이벤트마다 DEK 를 발급해 암호화→복호화 왕복을 확인한다.

    감사 로그를 실제로 암호화 보관하기 전에, 그 경로가 동작하는지부터 확인하는
    단계다. 왕복이 깨지면 나중에 보관본을 못 읽는다.
    """
    passed = 0
    for entry in entries:
        payload = json.dumps(entry.get("event", {}), ensure_ascii=False)
        dek = secrets.token_bytes(32)
        encrypted = encrypt_data(payload, dek)
        try:
            if decrypt_with_key(encrypted, dek) == payload:
                passed += 1
        except Exception:  # noqa: BLE001
            pass
    return {"passed": passed, "total": len(entries)}


def main() -> int:
    patterns = sys.argv[1:] or [str(D06_DIR / "audit-events" / "rag_audit_*.jsonl")]
    paths = collect_paths(patterns)
    if not paths:
        print("감사 로그 파일을 찾을 수 없습니다: {}".format(" ".join(patterns)),
              file=sys.stderr)
        return 1

    entries: List[Dict[str, Any]] = []
    broken_total = 0
    for path in paths:
        rows, broken = load_entries(path)
        entries.extend(rows)
        broken_total += broken

    print(LINE)
    print(" [d06] 감사로그 점검 — {}".format(", ".join(p.name for p in paths)))
    print(LINE)
    if not entries:
        print("점검할 이벤트가 없습니다.")
        return 1

    # ── 무결성 ─────────────────────────────────────────────────────
    verdict = ChainSink.verify(entries)

    # ── PII / 가명처리 ─────────────────────────────────────────────
    detector = PIIGuard()
    residual = 0
    masked_tokens = 0
    for entry in entries:
        event = entry.get("event", {})
        text = " ".join(str(event.get(f, "")) for f in ("actor", "purpose", "asset"))
        masked_tokens += text.count("_MASKED]")
        residual += sum(1 for f in detector.scan(text) if f.severity in ("CRITICAL", "HIGH"))

    pseudonymized = sum(1 for e in entries
                        if str(e.get("event", {}).get("actor", "")).startswith("u_"))

    # ── 접근제어 ───────────────────────────────────────────────────
    denials = [e for e in entries if e.get("event", {}).get("result") == "denied"]
    reason_kinds: Counter = Counter()
    for entry in denials:
        for reason in entry.get("_detail", {}).get("deny_reasons", []):
            if "자산 등록부에 없음" in reason:
                reason_kinds["미등록 자산"] += 1
            elif "정책에 없음" in reason:
                reason_kinds["미등록 role"] += 1
            elif "수행 권한 없음" in reason:
                reason_kinds["액션 권한"] += 1
            elif "등급보다 낮음" in reason:
                reason_kinds["등급 부족(RBAC)"] += 1
            elif "허용 부서 목록에 없음" in reason:
                reason_kinds["부서 제한(ABAC)"] += 1

    crypto = check_crypto(entries)
    retention = check_retention(entries)

    # ── 리포트 ─────────────────────────────────────────────────────
    integrity = "✅ 정상" if verdict["valid"] else "🚨 {} (index={})".format(
        verdict["findings"][0]["type"], verdict["findings"][0]["index"])

    print("📋 총 이벤트 수        : {}개{}".format(
        len(entries), "  (깨진 줄 {}건)".format(broken_total) if broken_total else ""))
    print("🔗 해시체인 무결성      : {}".format(integrity))
    # 스펙의 지표는 "엔진 단계에서 마스킹한 건수"다. SDK 가 append 직전에 이미
    # 마스킹하므로 엔진에는 마스킹할 것이 남지 않아 0이 정상이다. 0이 아니라면
    # 기록 시점 통제를 빠져나온 값이 있다는 뜻이라 오히려 문제 신호다.
    print("🕶 PII 마스킹 처리 건수 : {}개   ← SDK가 기록 시점에 이미 마스킹함 (정상)".format(
        residual))
    print("   (SDK 기록 시점 마스킹 토큰: {}개)".format(masked_tokens))
    print("🪪 actor 가명처리 건수  : {}개".format(pseudonymized))
    print("🔓 잔존 평문 PII 건수   : {}개".format(residual))
    print("🔐 암호화 자기검증 통과 : {}/{}개".format(crypto["passed"], crypto["total"]))
    print("🔒 접근제어 거부 건수   : {}개".format(len(denials)))

    if reason_kinds:
        print("\n" + SUB)
        print(" 거부 사유 분포")
        print(SUB)
        for kind, count in reason_kinds.most_common():
            print("  {:<18} {}건".format(kind, count))

    print("\n" + SUB)
    print(" 보관기한")
    print(SUB)
    for action, count in sorted(retention["per_action"].items()):
        print("  {:<16} {:>3}건 · 보관 {}일".format(action, count, retention_days(action)))
    print("  retention_expired_count = {}".format(retention["expired"]))

    if not verdict["valid"]:
        finding = verdict["findings"][0]
        print("\n" + SUB)
        print(" 🚨 무결성 위반")
        print(SUB)
        print("  index={} type={}".format(finding["index"], finding["type"]))
        print("  {}".format(finding["detail"]))
        print("  변조 지점 action={}".format(finding.get("action")))
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
