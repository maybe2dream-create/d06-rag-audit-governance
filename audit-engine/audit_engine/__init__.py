"""
[Lab 10 - Step 5] audit_engine — Step 02/03/04 통합 감사 로그 엔진 패키지
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
기존 lab10_step01~04 모듈에 의존하지 않는 독립 패키지입니다. (plan.md B.3)

  from audit_engine import IntegratedAuditEngine, AuditHashChain, AuditRetentionEngine
"""

from .crypto import AuditCryptoEngine, KeyNotFoundError, KeyVault
from .hash_chain import AuditHashChain
from .models import AuditEvent, AuditLogEntry, parse_audit_events
from .retention import AuditRetentionEngine

__all__ = [
    "AuditEvent",
    "AuditLogEntry",
    "parse_audit_events",
    "AuditHashChain",
    "AuditRetentionEngine",
    "AuditCryptoEngine",
    "KeyVault",
    "KeyNotFoundError",
    "IntegratedAuditEngine",
]

__version__ = "1.0.0"


def __getattr__(name):
    # 오케스트레이터는 순환 import 방지를 위해 지연 로딩
    if name == "IntegratedAuditEngine":
        from .lab10_step05_audit_engine import IntegratedAuditEngine
        return IntegratedAuditEngine
    raise AttributeError(f"module 'audit_engine' has no attribute '{name}'")
