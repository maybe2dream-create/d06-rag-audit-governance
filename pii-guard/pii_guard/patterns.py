"""개인정보·민감정보 탐지 규칙과 검증기.

■ 검증기가 규칙의 절반이다:
  정규식만 쓰면 `900101-9999999` 같은 임의 숫자열도 주민등록번호로 잡힌다.
  오탐이 쌓이면 리포트를 아무도 안 보게 되고, 그러면 탐지기가 있으나 마나다.
  그래서 형식이 정해진 항목(주민등록번호·카드번호)은 **체크섬까지 통과한 것만**
  CRITICAL 로 올리고, 통과하지 못하면 등급을 낮춰 별도로 표시한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1}

# RFC 2606 / 6761 예약 도메인. 문서·테스트에 쓰라고 정해둔 것이라 실제 개인정보가 아니다.
RESERVED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net",
                          "example.invalid", "example.test", "localhost", "invalid", "test")


# ─────────────────────────────────────────────────────────── 검증기

def validate_rrn(value: str) -> bool:
    """주민등록번호 체크섬 + 생년월일 타당성 검증."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13:
        return False

    month, day = int(digits[2:4]), int(digits[4:6])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    if digits[6] not in "1234":       # 성별·세기 구분자 (외국인 5~8 은 아래에서 허용)
        if digits[6] not in "5678":
            return False

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(d) * w for d, w in zip(digits[:12], weights))
    return (11 - (total % 11)) % 10 == int(digits[12])


def validate_luhn(value: str) -> bool:
    """카드번호 Luhn 검증."""
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum, parity = 0, len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def validate_email(value: str) -> bool:
    """예약 도메인은 실제 개인정보가 아니므로 제외한다."""
    domain = value.rsplit("@", 1)[-1].lower()
    return not any(domain == d or domain.endswith("." + d) for d in RESERVED_EMAIL_DOMAINS)


def validate_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 9 or len(digits) > 11:
        return False
    return digits.startswith("01") or digits.startswith("02") or digits.startswith("0")


def validate_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ─────────────────────────────────────────────────────────── 마스킹

def mask_keep_prefix(value: str, keep: int) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "".join("*" if c.isalnum() else c for c in value[keep:])


def mask_rrn(value: str) -> str:
    """생년월일·성별자리까지만 남긴다 (통계는 가능, 식별은 불가)."""
    return mask_keep_prefix(value, 8)


def mask_card(value: str) -> str:
    """앞 4자리와 뒤 4자리만 남긴다."""
    body = list(value)
    seen = [i for i, c in enumerate(body) if c.isdigit()]
    for i in seen[4:-4]:
        body[i] = "*"
    return "".join(body)


def mask_phone(value: str) -> str:
    body = list(value)
    seen = [i for i, c in enumerate(body) if c.isdigit()]
    for i in seen[3:-4]:
        body[i] = "*"
    return "".join(body)


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    head = local[:1] if local else ""
    return "{}{}@{}".format(head, "*" * max(len(local) - 1, 1), domain)


def mask_generic(value: str) -> str:
    return mask_keep_prefix(value, 2)


# ─────────────────────────────────────────────────────────── 규칙

@dataclass(frozen=True)
class Rule:
    rule_id: str
    label: str
    severity: str
    pattern: Pattern
    validator: Optional[Callable[[str], bool]] = None
    masker: Optional[Callable[[str], str]] = None
    # 검증에 실패했을 때 내려앉을 등급. None 이면 아예 버린다.
    demoted_severity: Optional[str] = None
    # 토큰 치환용 이름. [PHONE_MASKED] 처럼 값을 통째로 대체할 때 쓴다.
    token_name: str = ""

    def mask(self, value: str) -> str:
        return (self.masker or mask_generic)(value)

    @property
    def token(self) -> str:
        """[RRN_MASKED] 형태의 치환 토큰."""
        name = self.token_name or self.rule_id.split("-")[-1]
        return "[{}_MASKED]".format(name.upper())


RULES: List[Rule] = [
    Rule("PII-RRN", "주민등록번호", CRITICAL,
         re.compile(r"\b\d{6}[-\s]?[1-8]\d{6}\b"),
         validate_rrn, mask_rrn, demoted_severity=MEDIUM),

    Rule("PII-CARD", "신용카드번호", CRITICAL,
         re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
         validate_luhn, mask_card, demoted_severity=MEDIUM),

    Rule("SEC-CRED", "API 키·토큰", CRITICAL,
         re.compile(r"\b(?:AIza[0-9A-Za-z_\-]{35}|gho_[0-9A-Za-z]{36}"
                    r"|sk-[0-9A-Za-z]{20,}|ghp_[0-9A-Za-z]{36})\b"),
         None, lambda v: mask_keep_prefix(v, 4)),

    # 전화번호를 계좌번호보다 먼저 둔다. 둘 다 HIGH 라 심각도로는 우열이 갈리지
    # 않으므로, 겹칠 때 먼저 선언된 규칙이 남는다. 010-1234-5678 은 전화번호다.
    Rule("PII-PHONE", "전화번호", HIGH,
         re.compile(r"(?<![\d-])0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}(?![\d-])"),
         validate_phone, mask_phone),

    # 앞뒤로 숫자·하이픈이 더 붙어 있으면 계좌번호가 아니다 (카드번호의 일부일 수 있다).
    # 0 으로 시작하는 것은 전화번호이므로 제외한다.
    Rule("PII-ACCOUNT", "계좌번호", HIGH,
         re.compile(r"(?<![\d-])(?!0)\d{2,4}-\d{2,6}-\d{4,8}(?![\d-])"),
         None, mask_generic),

    Rule("PII-PASSPORT", "여권번호", HIGH,
         re.compile(r"\b[MSRODmsrod]\d{8}\b"),
         None, lambda v: mask_keep_prefix(v, 2)),

    Rule("PII-EMAIL", "이메일", MEDIUM,
         re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
         validate_email, mask_email),

    Rule("PII-ADDR", "주소", MEDIUM,
         re.compile(r"(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남"
                    r"|전북|전남|경북|경남|제주)[^\n]{0,25}?(?:로|길|동|읍|면|가)\s*\d+"),
         None, lambda v: mask_keep_prefix(v, 6)),

    Rule("PII-IP", "IP 주소", LOW,
         re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
         validate_ipv4, lambda v: v.rsplit(".", 1)[0] + ".*"),
]

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}
