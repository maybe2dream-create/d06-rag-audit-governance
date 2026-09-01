"""
[Lab 10 - Step 5 / audit_engine] 감사 로그 5W1H 스키마 정의
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
plan.md B.3 내용 구현:
- 기존 lab10_step01~04 모듈을 import 하지 않고 스키마를 자체 정의하여 완전 독립 동작 보장
- Step 01 원시 감사로그(JSON) 및 Step 02 해시체인(JSON) 두 포맷을 모두 자동 인식하여 역직렬화
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields


@dataclass(frozen=True)
class AuditEvent:
    """5W1H 감사 이벤트 스키마 (When/Who/What/Where/Why/How + Result)"""

    timestamp: str = ""    # When (UTC)
    actor: str = ""        # Who (사용자/시스템 식별자)
    role: str = ""         # Who (권한/역할)
    department: str = ""   # Who (소속 부서)
    action: str = ""       # How (수행 행위)
    asset: str = ""        # What (대상 자산)
    record_id: str = ""    # What (대상 레코드 ID)
    source_ip: str = ""    # Where (접속 IP)
    purpose: str = ""      # Why (작업 목적/사유)
    result: str = ""       # Result (성공/실패/거부)

    @classmethod
    def field_names(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        """알 수 없는 키는 무시하고 누락 키는 기본값으로 채워 관대하게 역직렬화"""
        known = cls.field_names()
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)

    def replace_field(self, field_name: str, value: str) -> "AuditEvent":
        """frozen 데이터클래스의 단일 필드를 교체한 새 인스턴스 반환 (변조 시뮬레이션용)"""
        if field_name not in self.field_names():
            raise KeyError(f"AuditEvent에 존재하지 않는 필드입니다: {field_name}")
        return AuditEvent(**{**self.to_dict(), field_name: value})


@dataclass(frozen=True)
class AuditLogEntry:
    """이전 해시와 연쇄 결합된 감사 로그 체인 엔트리"""

    event: AuditEvent
    previous_hash: str
    entry_hash: str

    def to_dict(self) -> dict:
        return {
            "event": self.event.to_dict(),
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


def parse_audit_events(raw_json: list) -> list[AuditEvent]:
    """원시 감사로그 포맷과 해시체인 포맷을 모두 자동 판별하여 AuditEvent 리스트로 변환"""
    events: list[AuditEvent] = []
    if not isinstance(raw_json, list):
        raise ValueError("감사로그 JSON 최상위는 리스트여야 합니다.")

    for item in raw_json:
        if not isinstance(item, dict):
            continue
        # 해시체인 결과 파일({"event": {...}, "previous_hash": ...})도 그대로 수용
        payload = item["event"] if "event" in item and isinstance(item["event"], dict) else item
        events.append(AuditEvent.from_dict(payload))

    return events
