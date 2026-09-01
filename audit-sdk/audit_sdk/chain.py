"""기록 시점 해시체인 싱크.

감사 이벤트를 append 하기 직전에 직전 엔트리의 `entry_hash` 를 물려 체인을 잇는다.
배치로 나중에 체인을 만드는 방식은 **적재~배치 사이의 변조를 기준선으로 굳혀버린다.**
기록되는 순간 봉인해야 그 공백이 사라진다.

한 줄 구조:
    {"event": {5W1H 10필드}, "previous_hash": "...", "entry_hash": "...", "_detail": {...}}

■ 해시 대상은 event 10필드뿐이다:
  `_detail`(score·rank·path·tool_name 등)은 해시에 들어가지 않는다. 즉 `_detail` 변조는
  탐지되지 않는 **잔여위험**이다. 핵심 식별자(doc_id·model)는 `asset` 에 넣어 보호한다.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import fcntl  # POSIX 전용. 없으면 잠금 없이 동작한다.
except ImportError:  # pragma: no cover
    fcntl = None

GENESIS = "GENESIS"
FAILURE_LOG = "_sdk_failures.log"


def canonical(event: Dict[str, Any]) -> str:
    """해시 입력을 만들 때 키 순서·공백이 흔들리면 같은 내용이 다른 해시가 된다."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(event: Dict[str, Any], previous_hash: str) -> str:
    payload = previous_hash + "|" + canonical(event)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ChainSink:
    """일자별 JSONL 싱크. 기록 시점에 체인을 잇는다."""

    def __init__(self, sink_dir, prefix: str = "rag_audit"):
        self.sink_dir = Path(sink_dir)
        self.prefix = prefix

    # ------------------------------------------------------------ 경로
    def path_for(self, when: Optional[datetime] = None) -> Path:
        stamp = (when or datetime.now()).strftime("%Y%m%d")
        return self.sink_dir / "{}_{}.jsonl".format(self.prefix, stamp)

    @property
    def failure_log(self) -> Path:
        return self.sink_dir / FAILURE_LOG

    # ------------------------------------------------------------ tip 복구
    @staticmethod
    def read_tip(path: Path) -> str:
        """파일 마지막 줄에서 체인 끝 해시를 되살린다.

        프로세스가 재시작돼도 tip 을 메모리에 들고 있지 않고 매번 파일에서 읽으므로
        체인이 genesis 로 되돌아가지 않는다(T-23). 동시에 여러 프로세스가 써도
        잠금 안에서 이 값을 읽으므로 분기가 생기지 않는다(T-24).
        """
        if not path.exists() or path.stat().st_size == 0:
            return GENESIS
        last = ""
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return GENESIS
        try:
            return json.loads(last).get("entry_hash", GENESIS)
        except json.JSONDecodeError:
            return GENESIS

    # ------------------------------------------------------------ 기록
    def append(self, event: Dict[str, Any],
               detail: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """이벤트 한 건을 체인에 이어 붙인다.

        감사 기록 실패가 서비스 응답을 막아서는 안 된다. 실패는 삼키되
        `_sdk_failures.log` 와 stderr 에 남겨 조용히 사라지지 않게 한다(T-21).
        """
        try:
            self.sink_dir.mkdir(parents=True, exist_ok=True)
            path = self.path_for()

            # 잠금 안에서 tip 읽기 → 해시 계산 → append 를 원자적으로 수행한다.
            # 잠금 밖에서 tip 을 읽으면 두 프로세스가 같은 previous_hash 를 보고
            # 체인이 갈라진다.
            with open(path, "a+", encoding="utf-8") as handle:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    previous = self.read_tip(path)
                    entry = {
                        "event": event,
                        "previous_hash": previous,
                        "entry_hash": compute_hash(event, previous),
                    }
                    if detail:
                        entry["_detail"] = detail
                    handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                finally:
                    if fcntl is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return entry
        except Exception as exc:  # noqa: BLE001
            self._record_failure(exc, event)
            return None

    def _record_failure(self, exc: Exception, event: Dict[str, Any]) -> None:
        message = "[audit_sdk] 감사 기록 실패: {}: {}".format(exc.__class__.__name__, exc)
        print(message, file=sys.stderr)
        try:
            self.sink_dir.mkdir(parents=True, exist_ok=True)
            with open(self.failure_log, "a", encoding="utf-8") as handle:
                handle.write("{} | {} | action={} record_id={}\n".format(
                    datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), message,
                    event.get("action", "?"), event.get("record_id", "?")))
        except Exception:  # noqa: BLE001 - 실패 로그마저 실패하면 stderr 로 끝낸다
            pass

    # ------------------------------------------------------------ 검증
    @staticmethod
    def verify(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """체인을 처음부터 다시 계산해 무결성을 검증한다."""
        findings: List[Dict[str, Any]] = []
        expected_previous = GENESIS

        for index, entry in enumerate(entries, start=1):
            event = entry.get("event", {})
            previous = entry.get("previous_hash", "")
            recorded = entry.get("entry_hash", "")

            if previous != expected_previous:
                findings.append({
                    "index": index,
                    "type": "previous_hash_mismatch",
                    "detail": "이전 해시 링크가 끊어졌습니다 (삭제 또는 순서 교환)",
                    "action": event.get("action"),
                })
                break

            if compute_hash(event, previous) != recorded:
                findings.append({
                    "index": index,
                    "type": "entry_hash_mismatch",
                    "detail": "기록된 해시와 재계산 해시가 다릅니다 (내용 위조)",
                    "action": event.get("action"),
                })
                break

            expected_previous = recorded

        return {"valid": not findings, "checked": len(entries), "findings": findings}


def load_entries(path) -> Tuple[List[Dict[str, Any]], int]:
    """JSONL 싱크를 읽어 엔트리와 깨진 줄 수를 반환한다."""
    entries: List[Dict[str, Any]] = []
    broken = 0
    path = Path(path)
    if not path.exists():
        return entries, broken
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                broken += 1
    return entries, broken
