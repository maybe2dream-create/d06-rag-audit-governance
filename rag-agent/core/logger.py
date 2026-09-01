"""Stage 4 로그 공통 모듈.

역할:
- 일반 앱 로그와 보안 로그를 분리한다.
- 로그 디렉터리를 자동 생성한다.
- 로그 직전 마스킹을 적용한다.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import LOG_DIR
from core.masking import mask_mapping


APP_LOGGER_NAME = "rag_agent_app"
SECURITY_LOGGER_NAME = "rag_agent_security"


def _build_logger(name: str, file_name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    file_handler = logging.FileHandler(Path(LOG_DIR) / file_name, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


app_logger = _build_logger(APP_LOGGER_NAME, "app.log")
security_logger = _build_logger(SECURITY_LOGGER_NAME, "security.log")


def _serialize(payload: Dict[str, Any]) -> str:
    return json.dumps(mask_mapping(payload), ensure_ascii=False, default=str)


def log_app_event(message: str, payload: Optional[Dict[str, Any]] = None) -> None:
    app_logger.info("%s | %s", message, _serialize(payload or {}))


def log_security_event(message: str, payload: Optional[Dict[str, Any]] = None) -> None:
    security_logger.warning("%s | %s", message, _serialize(payload or {}))
