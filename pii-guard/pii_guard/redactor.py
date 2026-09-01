"""탐지된 개인정보에 통제 조치를 적용한다 (비식별 처리)."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Dict, List, Tuple

from .detector import Finding
from .patterns import RULES_BY_ID

ALLOW = "allow"
MASK = "mask"
PSEUDONYMIZE = "pseudonymize"
DROP = "drop"
BLOCK = "block"
TOKEN = "token"

ACTIONS = (ALLOW, MASK, PSEUDONYMIZE, DROP, BLOCK, TOKEN)


def _load_pseudonym_key() -> bytes:
    """가명처리 키.

    환경변수에 없으면 프로세스마다 새로 만든다. 그러면 같은 값이 실행마다 다른
    토큰이 되어 **재실행 간 통계·추적이 끊긴다.** 운영에서는 반드시 고정 키를
    `.env` 의 PII_PSEUDONYM_KEY 로 주입해야 한다.
    """
    raw = os.getenv("PII_PSEUDONYM_KEY", "").strip()
    if raw:
        return raw.encode("utf-8")
    return secrets.token_bytes(32)


class Redactor:
    """조치별 치환 문자열을 만든다."""

    def __init__(self, pseudonym_key: bytes = None):
        self.pseudonym_key = pseudonym_key or _load_pseudonym_key()
        self.ephemeral_key = not os.getenv("PII_PSEUDONYM_KEY", "").strip()

    def pseudonym(self, finding: Finding) -> str:
        """같은 값 → 같은 토큰. 토큰 → 원본은 불가.

        마스킹과 달리 값이 같은지 다른지를 비교할 수 있어, 원본 없이도
        '같은 사람이 3번 문의했다' 같은 통계를 낼 수 있다.
        """
        digest = hmac.new(self.pseudonym_key, finding.raw.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        return "[{}:{}]".format(finding.rule_id.split("-")[-1], digest[:6])

    def replacement(self, finding: Finding, action: str) -> str:
        if action == MASK:
            rule = RULES_BY_ID.get(finding.rule_id)
            return rule.mask(finding.raw) if rule else finding.preview
        if action == PSEUDONYMIZE:
            return self.pseudonym(finding)
        if action == TOKEN:
            # [RRN_MASKED] 처럼 값을 통째로 토큰으로 바꾼다.
            # 형식조차 남기지 않으므로 로그만 보고는 원본 길이도 알 수 없다.
            rule = RULES_BY_ID.get(finding.rule_id)
            return rule.token if rule else "[PII_MASKED]"
        if action == DROP:
            return "[REDACTED:{}]".format(finding.rule_id)
        return finding.raw

    def apply(self, text: str, findings: List[Finding],
              actions: Dict[str, str]) -> Tuple[str, List[Dict[str, str]]]:
        """findings 를 뒤에서부터 치환한다.

        앞에서부터 바꾸면 치환 길이가 달라 뒤쪽 offset 이 전부 어긋난다.
        """
        applied: List[Dict[str, str]] = []
        result = text
        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            action = actions.get(finding.rule_id, MASK)
            if action in (ALLOW, BLOCK):
                continue
            replacement = self.replacement(finding, action)
            result = result[:finding.start] + replacement + result[finding.end:]
            applied.append({
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "action": action,
                "replacement": replacement,
            })
        return result, list(reversed(applied))
