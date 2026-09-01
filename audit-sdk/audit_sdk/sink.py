"""감사 이벤트 저장소(sink).

기본은 append-only JSONL 이다.

■ JSON 배열이 아니라 JSONL 인 이유:
  JSON 배열은 기록마다 파일 전체를 다시 써야 해서 앞선 기록을 덮어쓸 여지가 생긴다.
  JSONL 은 끝에 한 줄 붙이는 것이 전부라 이미 쓴 기록을 건드리지 않는다.
  감사엔진이 기대하는 JSON 배열로의 변환은 배치 시점에 pipeline 이 맡는다.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List


class AuditSink:
    """저장소 인터페이스."""

    def write(self, event: Dict[str, Any]) -> None:
        raise NotImplementedError


class JsonlSink(AuditSink):
    """append-only JSONL 파일 저장소."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, event: Dict[str, Any]) -> None:
        # 감사 기록 실패가 서비스 응답을 막아서는 안 된다. 예외는 삼키되
        # 표준 에러로 알려 조용히 사라지지 않게 한다.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except Exception as exc:  # noqa: BLE001
            print("[audit_sdk] 감사 이벤트 적재 실패: {}".format(exc), file=sys.stderr)

    def read_all(self):
        """적재된 이벤트와 건너뛴 깨진 줄 수를 반환한다."""
        events: List[Dict[str, Any]] = []
        broken = 0
        if not self.path.exists():
            return events, broken

        with open(self.path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # 깨진 줄에서 멈추지 않고 센다. 조용히 버리면 감사 기록이
                    # 사라진 사실 자체를 모르게 된다.
                    broken += 1
                    continue
                if isinstance(record, dict):
                    events.append(record)
                else:
                    broken += 1
        return events, broken


class MemorySink(AuditSink):
    """테스트용 인메모리 저장소."""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def write(self, event: Dict[str, Any]) -> None:
        self.events.append(event)

    def read_all(self):
        return list(self.events), 0
