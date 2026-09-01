"""d06 — 개인정보·민감정보 일괄 스캐너.

서비스 학습 데이터 / 추론 로그 / 사용자 피드백 로그 세 클래스를 한 번에 훑어
잔여 개인정보를 탐지하고 리포트를 산출한다.

탐지만 한다. 원본 파일은 건드리지 않는다 — 이미 쌓인 로그의 소급 정제는
별도 판단이 필요한 일이고, 스캐너가 조용히 해버릴 일이 아니다.

사용 방법:
  $ python3 scan_pii.py                       # 세 클래스 전체
  $ python3 scan_pii.py --class training_data # 한 클래스만
  $ python3 scan_pii.py --quiet               # 요약만
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

D06_DIR = Path(__file__).resolve().parent
SDK_DIR = D06_DIR / "pii-guard"
if SDK_DIR.is_dir() and str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from pii_guard import (  # noqa: E402
    AUDIT_EVENT, FEEDBACK_LOG, INFERENCE_LOG, TRAINING_DATA, PIIPolicy,
)
from pii_guard.report import build_payload, save_markdown  # noqa: E402
from pii_guard.scanner import PIIScanner, aggregate, save_json  # noqa: E402

LINE = "=" * 88
SUB = "-" * 88

MARK = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}

POLICY_PATH = D06_DIR / "configs" / "pii_policy.json"

# 데이터 클래스별 스캔 대상.
#
# audit_out 을 inference_log 와 섞지 않는 이유:
#   audit_out/*.jsonl 은 평문으로 방치되는 로그가 아니라 감사엔진의 입력이다.
#   Stage 3 에서 DEK 로 암호화되고 Crypto-Shredding 대상이 된다. 통제 주체가 다르므로
#   같은 클래스로 묶으면 "통제 안 된 개인정보"로 잘못 집계된다.
TARGETS = {
    TRAINING_DATA: [
        D06_DIR / "rag-agent" / "documents.json",
        D06_DIR / "testdata",
    ],
    INFERENCE_LOG: [
        D06_DIR / "rag-agent" / "logs",
    ],
    FEEDBACK_LOG: [
        D06_DIR / "rag-agent" / "feedback_out",
    ],
    AUDIT_EVENT: [
        D06_DIR / "rag-agent" / "audit_out",
    ],
}

# 클래스별 통제 방식 — 리포트에 함께 보여준다.
CONTROL_NOTE = {
    TRAINING_DATA: "적재 시 마스킹 (원본 말뭉치에는 PII 가 있는 것이 정상)",
    INFERENCE_LOG: "기록 직전 마스킹  ← 통제 대상",
    FEEDBACK_LOG: "저장 직전 마스킹·가명처리  ← 통제 대상",
    AUDIT_EVENT: "감사엔진 암호화 + Crypto-Shredding",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="개인정보·민감정보 일괄 스캐너")
    parser.add_argument("--class", dest="data_class", choices=list(TARGETS),
                        help="한 데이터 클래스만 스캔")
    parser.add_argument("--quiet", action="store_true", help="파일별 상세 출력 생략")
    parser.add_argument("--label", default="", help="리포트 파일명에 붙일 라벨 (before/after 등)")
    args = parser.parse_args()

    print(LINE)
    print(" [d06] 개인정보·민감정보 일괄 스캔")
    print(LINE)

    targets = {args.data_class: TARGETS[args.data_class]} if args.data_class else TARGETS
    scanner = PIIScanner()
    scans = scanner.scan_classes(targets)

    stats = aggregate(scans)
    totals = stats["totals"]

    print(SUB)
    print(" 데이터 클래스별 탐지 현황")
    print(SUB)
    print("  {:<15} {:>5} {:>9} {:>5} {:>5} {:>5}  {}".format(
        "데이터 클래스", "파일", "CRITICAL", "HIGH", "MED", "LOW", "통제 방식"))
    for name, bucket in stats["by_class"].items():
        print("  {:<15} {:>5} {:>9} {:>5} {:>5} {:>5}  {}".format(
            name, bucket["files"],
            bucket.get("CRITICAL", 0), bucket.get("HIGH", 0),
            bucket.get("MEDIUM", 0), bucket.get("LOW", 0),
            CONTROL_NOTE.get(name, "-")))

    if stats["by_rule"]:
        print("\n" + SUB)
        print(" 규칙별 탐지")
        print(SUB)
        for rule_id, entry in stats["by_rule"].items():
            print("  {} {:<14} {:<12} {}건".format(
                MARK.get(entry["severity"], " "), rule_id, entry["label"], entry["count"]))

    if not args.quiet:
        hits = [scan for scan in scans if scan.findings]
        if hits:
            print("\n" + SUB)
            print(" 파일별 상세 (값은 마스킹됨)")
            print(SUB)
            for scan in hits:
                rel = Path(scan.path).relative_to(D06_DIR)
                print("  📄 {}  [{}]".format(rel, scan.data_class))
                for finding in scan.findings:
                    validated = {True: "검증통과", False: "검증실패→등급하향",
                                 None: "—"}[finding.validated]
                    print("     {} {:<14} {:<8} {:<18} {}".format(
                        MARK.get(finding.severity, " "), finding.rule_id,
                        finding.severity, validated, finding.preview))

    # 산출물 저장
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "_{}".format(args.label) if args.label else ""
    out_dir = D06_DIR / "outputs"
    json_path = save_json(build_payload(scans), out_dir / "pii_scan_{}{}.json".format(stamp, suffix))
    md_path = save_markdown(scans, out_dir / "pii_scan_{}{}.md".format(stamp, suffix))

    print("\n" + SUB)
    print(" 결과")
    print(SUB)
    print("  스캔 파일 {}개 · 총 탐지 {}건 "
          "(CRITICAL {} · HIGH {} · MEDIUM {} · LOW {})".format(
              stats["files_scanned"], totals["total"], totals["CRITICAL"],
              totals["HIGH"], totals["MEDIUM"], totals["LOW"]))
    print("  📄 JSON     : {}".format(json_path))
    print("  📄 Markdown : {}".format(md_path))

    # 종료 코드는 "통제 후 반드시 깨끗해야 하는" 클래스만 본다.
    # 원본 말뭉치(training_data)와 암호화 대상(audit_event)까지 실패로 세면
    # 항상 빨간불이 켜져서 신호로서 쓸모가 없어진다.
    policy = PIIPolicy.load(POLICY_PATH)
    enforced = [c for c in policy.enforced_classes if c in stats["by_class"]]
    residual = sum(stats["by_class"][c].get("CRITICAL", 0) for c in enforced)

    print("  통제 강제 대상 : {} → 잔여 CRITICAL {}건".format(
        ", ".join(enforced) or "-", residual))

    if residual:
        print("\n  🚨 통제 대상 클래스에 CRITICAL {}건이 남아 있다.".format(residual))
        return 2
    print("\n  ✅ 통제 대상 클래스 잔여 CRITICAL 0건")
    return 0


if __name__ == "__main__":
    sys.exit(main())
