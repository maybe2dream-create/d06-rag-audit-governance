"""tests/tamper.py — 감사 로그 변조 케이스 생성기.

해시체인이 실제로 변조를 잡는지 확인하려면 변조된 로그가 있어야 한다.
원본은 건드리지 않고 케이스별 사본을 만든다.

  modify_result  결과값 위조   → entry_hash_mismatch (내용이 바뀌면 해시가 안 맞는다)
  modify_actor   행위자 위조   → entry_hash_mismatch (누가 했는지 지우는 전형적 은폐)
  delete_entry   이벤트 삭제   → previous_hash_mismatch (링크가 끊긴다)
  reorder        순서 교환     → previous_hash_mismatch (순서도 체인의 일부다)

사용 방법:
  python3 tests/tamper.py audit-events/rag_audit_20260901.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

CASES = ("modify_result", "modify_actor", "delete_entry", "reorder")


def load(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def save(rows: List[Dict[str, Any]], path: Path) -> Path:
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def target_index(rows: List[Dict[str, Any]]) -> int:
    """가운데 엔트리를 고른다. 첫/마지막은 경계라 탐지가 쉬워 대표성이 떨어진다."""
    return max(1, len(rows) // 2)


def apply_case(rows: List[Dict[str, Any]], case: str) -> List[Dict[str, Any]]:
    rows = json.loads(json.dumps(rows))   # 깊은 복사
    index = target_index(rows)

    if case == "modify_result":
        rows[index]["event"]["result"] = "tampered_success"
    elif case == "modify_actor":
        rows[index]["event"]["actor"] = "u_attacker0000"
    elif case == "delete_entry":
        del rows[index]
    elif case == "reorder":
        rows[index], rows[index - 1] = rows[index - 1], rows[index]
    else:
        raise ValueError("알 수 없는 케이스: {}".format(case))
    return rows


def main() -> int:
    if len(sys.argv) < 2:
        print("사용법: python3 tests/tamper.py <감사로그.jsonl>", file=sys.stderr)
        return 1

    source = Path(sys.argv[1])
    if not source.exists():
        print("파일이 없습니다: {}".format(source), file=sys.stderr)
        return 1

    rows = load(source)
    if len(rows) < 3:
        print("엔트리가 3건 미만이라 변조 케이스를 만들 수 없습니다.", file=sys.stderr)
        return 1

    print("원본: {} ({}건)".format(source, len(rows)))
    print("변조 대상 인덱스: {} (action={})".format(
        target_index(rows), rows[target_index(rows)]["event"].get("action")))
    print()

    for case in CASES:
        out = source.with_name("{}__{}{}".format(source.stem, case, source.suffix))
        save(apply_case(rows, case), out)
        print("  생성: {}".format(out.name))

    print("\n점검:")
    print("  for c in {}; do".format(" ".join(CASES)))
    print("    python3 run_audit_engine.py {}__${{c}}{} | grep -E '무결성|index='"
          .format(source.with_suffix("").name, source.suffix))
    print("  done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
