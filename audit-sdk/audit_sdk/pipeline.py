"""배치 파이프라인 — 적재된 감사 이벤트를 감사엔진에 투입한다.

■ 이 모듈만 감사엔진을 import 한다:
  `audit_sdk` 코어(event/context/sink/client/integrations)는 엔진 의존이 0이다.
  앱은 코어만 쓰므로, 감사 대상이 감사 도구의 검증 로직을 끌어오지 않는다.
  이 모듈은 배치 실행 쪽에서만 import 된다.

    from audit_sdk.pipeline import run_batch
    result = run_batch(client, engine_dir)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional


class EngineNotAvailable(RuntimeError):
    """감사엔진 패키지를 찾을 수 없을 때."""


def _load_engine(engine_dir):
    """감사엔진 패키지를 로드한다.

    'audit-engine' 폴더는 하이픈이 있어 패키지명이 될 수 없다. import 대상은 그 안의
    'audit_engine'(언더스코어) 패키지이므로 상위 폴더를 경로에 얹는다.
    """
    engine_dir = Path(engine_dir)
    if not (engine_dir / "audit_engine").is_dir():
        raise EngineNotAvailable(
            "감사엔진 패키지를 찾을 수 없습니다: {}/audit_engine".format(engine_dir)
        )
    if str(engine_dir) not in sys.path:
        sys.path.insert(0, str(engine_dir))

    from audit_engine.config_loader import (
        AuditEngineConfigLoader, current_time_suffix, save_json,
    )
    from audit_engine.lab10_step05_audit_engine import IntegratedAuditEngine

    return {
        "ConfigLoader": AuditEngineConfigLoader,
        "current_time_suffix": current_time_suffix,
        "save_json": save_json,
        "IntegratedAuditEngine": IntegratedAuditEngine,
    }


def convert_to_engine_input(events, engine_dir, time_suffix: str,
                            basename: str = "rag_audit_events") -> Path:
    """적재된 이벤트를 감사엔진이 읽는 JSON 배열 파일로 저장한다.

    엔진의 load_json() 은 JSON 배열을 기대하고 JSONL 은 읽지 못한다. 적재는
    append-only(JSONL)가 맞고 엔진 입력은 배열이 맞으므로, 여기서 형식을 맞춘다.
    """
    engine = _load_engine(engine_dir)
    raw_path = (Path(engine_dir) / "outputs" / "raw_events"
                / "{}_{}.json".format(basename, time_suffix))
    engine["save_json"](events, raw_path)
    return raw_path


def run_batch(
    client,
    engine_dir,
    config_path=None,
    rotate: bool = False,
    basename: str = "rag_audit_events",
    on_collected=None,
    on_converted=None,
) -> Dict[str, Any]:
    """적재 이벤트 → 형식 변환 → 감사엔진 실행까지 한 번에 수행한다.

    `on_collected(events, broken)` 와 `on_converted(raw_path, config_path)` 는
    호출자가 진행 상황을 **엔진이 출력을 쏟아내기 전에** 보여줄 수 있게 하는 훅이다.

    반환: {"events", "broken", "raw_path", "report", "archive", "config_path"}
    """
    engine = _load_engine(engine_dir)
    engine_dir = Path(engine_dir)

    events, broken = client.read_all()
    if on_collected:
        on_collected(events, broken)
    if not events:
        return {"events": [], "broken": broken, "raw_path": None,
                "report": None, "archive": None, "config_path": None}

    time_suffix = engine["current_time_suffix"]()
    raw_path = convert_to_engine_input(events, engine_dir, time_suffix, basename)

    config_path = Path(config_path) if config_path else \
        engine["ConfigLoader"].default_config_path(engine_dir)
    config = engine["ConfigLoader"].load(config_path)
    if on_converted:
        on_converted(raw_path, config_path)

    # 엔진은 base_dir 를 인자로 받으므로 패키지를 고치지 않고 d06 경로로 구동된다.
    orchestrator = engine["IntegratedAuditEngine"](engine_dir, config, config_path)
    report = orchestrator.run(str(raw_path))

    archive: Optional[Path] = client.rotate(time_suffix) if rotate else None

    return {
        "events": events,
        "broken": broken,
        "raw_path": raw_path,
        "report": report,
        "archive": archive,
        "config_path": config_path,
    }
