"""
[Lab 10 - Step 5 / audit_engine] Step 03 통합 - 법적/규정 보관 기간(Retention) 산출
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
plan.md B.4 Stage 2 내용 구현:
- Config의 retention_settings.policies에서 행위(action)별 보관 일수/근거 법률 매핑
- 이벤트 타임스탬프 기준 만료 예정일 산출 및 만료 여부(expired) 판정
- 타임스탬프 포맷 불량(감사 취약점 4) 로그는 파싱 실패를 기록하고 현재 시각으로 대체 산출
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import AuditEvent

FALLBACK_POLICY = {
    "retention_days": 365,
    "category": "일반 감사 로그 (1년)",
    "legal_basis": "일반 내부 보안 정책",
}


class AuditRetentionEngine:
    """외부 Config 기반 보관 기간 계산 엔진"""

    def __init__(self, retention_settings: dict | None = None):
        settings = retention_settings or {}
        self.policies: dict = settings.get("policies", {})
        self.default_policy: dict = settings.get("default_policy", FALLBACK_POLICY)

    @staticmethod
    def parse_timestamp(timestamp: str) -> tuple[datetime, bool]:
        """ISO8601 타임스탬프 파싱. 실패 시 (현재 UTC, False) 반환"""
        if not timestamp:
            return datetime.now(timezone.utc), False
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc), False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed, True

    def calculate(self, event: AuditEvent, now: datetime | None = None) -> dict:
        """단일 이벤트의 보관 기한·근거 법률·만료 여부 산출"""
        now = now or datetime.now(timezone.utc)
        policy = self.policies.get(event.action, self.default_policy)
        retention_days = int(policy.get("retention_days", FALLBACK_POLICY["retention_days"]))

        event_dt, timestamp_valid = self.parse_timestamp(event.timestamp)
        retention_until = event_dt + timedelta(days=retention_days)

        return {
            "record_id": event.record_id,
            "actor": event.actor,
            "action": event.action,
            "asset": event.asset,
            "event_timestamp": event.timestamp,
            "timestamp_valid": timestamp_valid,
            "policy_matched": event.action in self.policies,
            "retention_days": retention_days,
            "retention_until": retention_until.strftime("%Y-%m-%d"),
            "expired": retention_until <= now,
            "remaining_days": (retention_until - now).days,
            "category": policy.get("category", FALLBACK_POLICY["category"]),
            "legal_basis": policy.get("legal_basis", FALLBACK_POLICY["legal_basis"]),
        }

    def calculate_all(self, events: list[AuditEvent]) -> list[dict]:
        now = datetime.now(timezone.utc)
        return [self.calculate(ev, now=now) for ev in events]

    @staticmethod
    def summarize(results: list[dict]) -> dict:
        """보관 정책 산출 결과 통계 요약"""
        return {
            "total_events": len(results),
            "policy_matched": sum(1 for r in results if r["policy_matched"]),
            "default_policy_applied": sum(1 for r in results if not r["policy_matched"]),
            "invalid_timestamp": sum(1 for r in results if not r["timestamp_valid"]),
            "expired_records": sum(1 for r in results if r["expired"]),
            "max_retention_days": max((r["retention_days"] for r in results), default=0),
            "min_retention_days": min((r["retention_days"] for r in results), default=0),
        }
