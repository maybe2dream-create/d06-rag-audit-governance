"""d06 브리지 CLI — 적재된 감사 이벤트를 감사엔진 배치 파이프라인에 투입한다.

흐름:
  rag-agent/audit_out/rag_audit_events.jsonl   (SDK 가 append-only 로 적재)
      ↓ audit_sdk.pipeline: JSONL → JSON 배열 변환
  audit-engine/outputs/raw_events/rag_audit_events_<타임스탬프>.json
      ↓ IntegratedAuditEngine (패키지 코드 무수정)
  Stage1 해시체인·변조탐지 → Stage2 보관정책 → Stage3 암호화·파기 → Stage4 리포트

변환과 엔진 호출은 전부 `audit_sdk.pipeline` 안에 있다. 이 파일은 얇은 CLI 다.

사용 방법:
  $ python3 run_audit_pipeline.py            # 전체 적재분 처리
  $ python3 run_audit_pipeline.py --rotate   # 처리분을 보관 파일로 옮기고 초기화
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

D06_DIR = Path(__file__).resolve().parent
ENGINE_DIR = D06_DIR / "audit-engine"
SDK_DIR = D06_DIR / "audit-sdk"

# SDK 를 정식 설치하지 않았어도 동작하도록 경로를 얹는다.
if SDK_DIR.is_dir() and str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from audit_sdk import AuditClient  # noqa: E402
from audit_sdk.pipeline import run_batch  # noqa: E402

LINE = "=" * 88
SUB = "-" * 88


def main() -> int:
    parser = argparse.ArgumentParser(description="RAG 감사 이벤트 → 감사엔진 배치 파이프라인")
    parser.add_argument("--rotate", action="store_true",
                        help="처리 후 적재 파일을 보관 파일로 옮기고 초기화한다")
    args = parser.parse_args()

    print(LINE)
    print(" [d06] RAG 감사 이벤트 → 감사엔진 배치 파이프라인 (audit_sdk)")
    print(LINE)

    # 앱과 같은 설정으로 클라이언트를 만들어 같은 적재 파일을 읽는다.
    audit = AuditClient(
        service="rag-service",
        out_dir=D06_DIR / "rag-agent" / "audit_out",
        filename="rag_audit_events.jsonl",
    )

    print(SUB)
    print(" [1/2] SDK 적재 이벤트 수집 및 형식 변환")
    print(SUB)
    print("  📥 적재 파일 : {}".format(audit.path))

    def on_collected(events, broken):
        print("  📊 이벤트 수 : {}건{}".format(
            len(events), " (깨진 줄 {}건 건너뜀)".format(broken) if broken else ""))
        if events:
            counts = Counter(event.get("action", "?") for event in events)
            print("  🏷️  action 분포 : "
                  + ", ".join("{} {}건".format(k, v) for k, v in sorted(counts.items())))

    def on_converted(raw_path, config_path):
        print("  💾 변환 저장 : {}".format(raw_path))
        print("\n" + SUB)
        print(" [2/2] 감사엔진 배치 실행")
        print(SUB)
        print("⚙️  전용 Config : {}\n".format(config_path))

    try:
        result = run_batch(audit, ENGINE_DIR, rotate=args.rotate,
                           on_collected=on_collected, on_converted=on_converted)
    except FileNotFoundError as exc:
        print("❌ {}".format(exc))
        return 1

    events = result["events"]
    if not events:
        print("❌ 처리할 이벤트가 없습니다.")
        print("   rag-agent 를 기동하고 요청을 보내 감사 이벤트를 쌓으세요.")
        return 1

    if result["archive"]:
        print("\n  🔄 적재 파일 보관 이동: {}".format(result["archive"]))

    verdict = result["report"]["verdict"]
    print("\n✅ d06 감사 파이프라인 완료 — RAG 이벤트 {}건 처리".format(len(events)))
    return 0 if verdict["overall_pass"] else 2


if __name__ == "__main__":
    sys.exit(main())
