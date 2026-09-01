"""
[Lab 10 - Step 5 / audit_engine] 통합 엔진 Config 로더 및 경로 해석 헬퍼
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
plan.md B.5 내용 구현:
- 전용 Config('configs/lab10_audit_engine_config.json') 로드
- 대상 감사로그 파일 3단 탐색: CLI 인자 > Config 지정 경로 > 최신 타임스탬프 파일 자동 추적
- 산출물 저장 경로에 _YYYYMMDD_HHMMSS 타임스탬프 자동 부여
"""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path

DEFAULT_CONFIG_FILENAME = "lab10_audit_engine_config.json"


class AuditEngineConfigLoader:
    """통합 엔진 외부 Config 로더"""

    @staticmethod
    def default_config_path(base_dir: Path) -> Path:
        return base_dir / "configs" / DEFAULT_CONFIG_FILENAME

    @staticmethod
    def load(config_path: str | Path) -> dict:
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config 파일을 찾을 수 없습니다: {config_path}")
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)


def resolve_input_file(base_dir: Path, config: dict, cli_override: str | None = None) -> Path:
    """CLI 인자 > Config target_file_path > 최신 타임스탬프 파일 순서로 대상 감사로그 탐색"""
    in_settings = config.get("input_settings", {})
    candidates: list[str] = []

    if cli_override:
        candidates.append(cli_override)
    target = in_settings.get("target_file_path")
    if target:
        candidates.append(target)

    for cand in candidates:
        cand_path = Path(cand)
        # 절대경로 → 현재 작업 디렉터리 기준 → 프로젝트 루트 기준 순으로 해석
        if cand_path.is_absolute():
            if cand_path.exists():
                return cand_path
        else:
            if cand_path.exists():
                return cand_path.resolve()
            joined = base_dir / cand
            if joined.exists():
                return joined

    # CLI로 명시 지정한 파일을 찾지 못했다면 자동 추적으로 대체하지 않고 즉시 실패시킨다.
    # (사용자가 지정한 것과 다른 파일을 조용히 처리하면 잘못된 대상을 검증하게 된다)
    if cli_override:
        raise FileNotFoundError(
            f"CLI로 지정한 대상 파일을 찾을 수 없습니다: {cli_override}\n"
            f"   • 현재 작업 디렉터리 기준: {Path.cwd() / cli_override}\n"
            f"   • 프로젝트 루트 기준    : {base_dir / cli_override}"
        )

    # 자동 추적: 지정 디렉터리 내 최신 타임스탬프 파일
    track_dir = base_dir / in_settings.get("auto_track_dir", "outputs/raw_events")
    pattern = in_settings.get("auto_track_pattern", "custom_audit_events_*.json")
    if track_dir.exists():
        matches = sorted(track_dir.glob(pattern), key=os.path.getmtime, reverse=True)
        if matches:
            return matches[0]

    raise FileNotFoundError(
        f"대상 감사로그 파일을 찾을 수 없습니다. (Config 지정: {target} / 자동추적: {track_dir}/{pattern})"
    )


def timestamped_path(base_dir: Path, dir_name: str, base_filename: str, time_suffix: str) -> Path:
    """'outputs/audit_engine/name_20260831_120000.json' 형태의 저장 경로 생성 (디렉터리 자동 생성)

    접미사가 초 단위이므로 같은 초 안에 두 번 기동하면 앞 회차 산출물이 덮어써진다.
    이미 존재하는 경로면 밀리초를 덧붙여 회차별 산출물을 모두 보존한다.
    """
    name, ext = os.path.splitext(base_filename)
    target_dir = base_dir / dir_name
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{name}_{time_suffix}{ext}"
    while path.exists():
        millis = datetime.now().strftime("%f")[:3]
        path = target_dir / f"{name}_{time_suffix}_{millis}{ext}"
    return path


def current_time_suffix() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def current_key_time_suffix() -> str:
    """DEK 식별자(data_id)에 결합할 실행 시각 접미사 (밀리초 단위)

    파일명 접미사(초 단위)와 달리 밀리초까지 포함한다.
    같은 초 안에 파이프라인이 두 번 기동되면 초 단위 접미사로는 data_id가 다시 겹쳐
    Key Vault의 DEK가 덮어써지기 때문이다.
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


def save_json(data, path: str | Path) -> Path:
    """JSON 산출물을 UTF-8로 영구 저장"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    return path


def load_json(path: str | Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
