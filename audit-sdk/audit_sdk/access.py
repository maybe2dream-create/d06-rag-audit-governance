"""AccessGuardEngine — 역할 기반 접근 통제 (RBAC + ABAC + deny-by-default).

■ deny-by-default 가 핵심이다:
  정책에 등록되지 않은 자산이나 role 은 **허용이 아니라 거부**로 판정한다.
  등록 누락은 흔한 일이고, 누락된 것을 조용히 통과시키면 정책이 있으나 마나가 된다.
  자산을 새로 추가하면서 등급 지정을 잊었을 때 그 사실이 거부로 드러나야 한다.

■ 관찰 전용(PEP 없음):
  거부 판정은 감사 이벤트로 기록되지만 응답을 막지는 않는다. 학습 환경에서 차단까지
  걸면 무엇이 왜 막혔는지 관찰하기 어렵기 때문이다. 집행이 필요하면 Config 의
  `enforcement_mode` 를 `enforce` 로 바꾼다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# 등급 서열. 숫자가 클수록 민감하다.
LEVEL_ORDER = {"public": 1, "internal": 2, "confidential": 3, "restricted": 4}

OBSERVE = "observe"
ENFORCE = "enforce"


@dataclass
class Decision:
    """단일 접근 판정."""

    allowed: bool
    action: str
    asset: str
    actor: str = ""
    role: str = ""
    department: str = ""
    reasons: List[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return " / ".join(self.reasons)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "asset": self.asset,
            "role": self.role,
            "department": self.department,
            "reasons": self.reasons,
        }


class AccessGuardEngine:
    """자산 등록부와 role 정책을 대조해 접근을 판정한다."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.assets: Dict[str, Any] = {
            k: v for k, v in config.get("assets", {}).items() if not k.startswith("_")
        }
        self.roles: Dict[str, Any] = {
            k: v for k, v in config.get("roles", {}).items() if not k.startswith("_")
        }
        self.enforcement_mode: str = config.get("enforcement_mode", OBSERVE)

    @classmethod
    def load(cls, path) -> "AccessGuardEngine":
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    @property
    def enforcing(self) -> bool:
        return self.enforcement_mode == ENFORCE

    def authorize(self, action: str, asset: str, actor: str = "",
                  role: str = "", department: str = "") -> Decision:
        """action·asset·신원을 대조해 허용/거부를 판정한다.

        거부 사유는 하나만 보고 끝내지 않고 전부 모은다. 등급도 부족하고 부서도
        안 맞는 경우 둘 다 알려줘야 정책을 고칠 수 있다.
        """
        decision = Decision(allowed=True, action=action, asset=asset,
                            actor=actor, role=role, department=department)

        # 1) 미등록 role — deny-by-default
        role_policy = self.roles.get(role)
        if role_policy is None:
            decision.allowed = False
            decision.reasons.append(
                "role '{}'가 정책에 없음 (deny-by-default)".format(role))
            return decision

        # 2) 액션 권한
        allowed_actions = role_policy.get("allowed_actions", [])
        if allowed_actions and action not in allowed_actions:
            decision.allowed = False
            decision.reasons.append(
                "role '{}'는 action '{}' 수행 권한 없음".format(role, action))

        # 자산이 걸리지 않는 action(턴 시작·종료 등)은 여기서 끝낸다.
        if not asset:
            return decision

        # 3) 미등록 자산 — deny-by-default
        asset_policy = self.assets.get(asset)
        if asset_policy is None:
            decision.allowed = False
            decision.reasons.append(
                "asset '{}'가 자산 등록부에 없음 (deny-by-default)".format(asset))
            return decision

        # 4) 등급 부족 (RBAC)
        asset_level = asset_policy.get("classification", "restricted")
        role_level = role_policy.get("clearance", "public")
        if LEVEL_ORDER.get(role_level, 0) < LEVEL_ORDER.get(asset_level, 99):
            decision.allowed = False
            decision.reasons.append(
                "role '{}'의 등급이 asset '{}' 등급보다 낮음".format(role, asset))

        # 5) 부서 제한 (ABAC)
        allowed_departments = asset_policy.get("allowed_departments", [])
        if allowed_departments and department not in allowed_departments:
            decision.allowed = False
            decision.reasons.append(
                "department '{}'는 asset '{}'의 허용 부서 목록에 없음".format(
                    department, asset))

        return decision


class DataClassifier:
    """자산 등록부를 근거로 데이터 보안등급을 매긴다."""

    def __init__(self, assets: Optional[Dict[str, Any]] = None):
        self.assets = assets or {}

    @classmethod
    def from_guard(cls, guard: AccessGuardEngine) -> "DataClassifier":
        return cls(guard.assets)

    def classify(self, asset: str) -> str:
        """등록되지 않은 자산은 가장 높은 등급으로 본다.

        모르는 데이터를 public 으로 취급하면 분류 누락이 곧 유출이 된다.
        """
        policy = self.assets.get(asset)
        if policy is None:
            return "unregistered"
        return policy.get("classification", "restricted")

    def owner(self, asset: str) -> str:
        policy = self.assets.get(asset)
        return policy.get("owner_department", "") if policy else ""
