"""
[Lab 10 - Step 5 / audit_engine] 파이프라인 단계별 중간 체크포인트 (Stage Checkpoints)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
각 스테이지의 경계에서 입력·출력 스냅샷을 남기고 **불변식(invariant)** 을 검사한다.

최종 판정만 보면 중간 단계에서 데이터가 소실·중복·오염되어도 결과가 그럴듯하면 통과한다.
(실제로 Stage 3의 DEK 키 충돌은 최종 판정이 PASS로 나와 은폐되었다 — plan.md E.2)
따라서 단계 경계마다 "무엇이 들어와 무엇이 나갔는지"와 "지켜져야 할 성질"을 따로 검증한다.

  CP-0  Stage 0 입력 로드      CP-3  Stage 2 보관정책 산출
  CP-1  Stage 1 체인 결합      CP-4  Stage 3 암호화·키보관
  CP-2  Stage 1 변조 탐지      CP-5  Stage 3 파기(Crypto-Shredding)
                               CP-6  Stage 4 리포트 병합
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import time


@dataclass
class Invariant:
    """단계 경계에서 반드시 성립해야 하는 성질"""

    name: str
    expected: str
    actual: str
    passed: bool

    def to_dict(self) -> dict:
        return {"name": self.name, "expected": self.expected,
                "actual": self.actual, "passed": self.passed}


@dataclass
class Checkpoint:
    """단일 체크포인트 기록"""

    cp_id: str
    stage: str
    name: str
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    invariants: list = field(default_factory=list)
    elapsed_ms: float = 0.0
    recorded_at: str = ""

    @property
    def passed(self) -> bool:
        return all(iv.passed for iv in self.invariants)

    @property
    def failed_invariants(self) -> list:
        return [iv for iv in self.invariants if not iv.passed]

    def to_dict(self) -> dict:
        return {
            "cp_id": self.cp_id,
            "stage": self.stage,
            "name": self.name,
            "recorded_at": self.recorded_at,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "inputs": self.inputs,
            "outputs": self.outputs,
            "invariants": [iv.to_dict() for iv in self.invariants],
            "passed": self.passed,
        }


class CheckpointRecorder:
    """체크포인트 수집기 — 스테이지 경계마다 호출되어 불변식을 검사하고 기록한다"""

    def __init__(self, enabled: bool = True, verbose: bool = True):
        self.enabled = enabled
        self.verbose = verbose
        self.checkpoints: list[Checkpoint] = []
        self._t0 = time.perf_counter()

    # ── 기록 ────────────────────────────────────────────────────────
    def record(self, cp_id: str, stage: str, name: str,
               inputs: dict = None, outputs: dict = None,
               invariants: list = None) -> Checkpoint:
        cp = Checkpoint(
            cp_id=cp_id, stage=stage, name=name,
            inputs=inputs or {}, outputs=outputs or {},
            invariants=invariants or [],
            elapsed_ms=(time.perf_counter() - self._t0) * 1000,
            recorded_at=datetime.now().strftime("%H:%M:%S.%f")[:-3],
        )
        if self.enabled:
            self.checkpoints.append(cp)
            if self.verbose:
                self._print(cp)
        return cp

    @staticmethod
    def inv(name: str, passed: bool, expected, actual) -> Invariant:
        """불변식 하나를 생성 (expected/actual은 문자열로 정규화)"""
        return Invariant(name=name, expected=str(expected), actual=str(actual), passed=bool(passed))

    # ── 출력 ────────────────────────────────────────────────────────
    def _print(self, cp: Checkpoint) -> None:
        mark = "✅" if cp.passed else "❌"
        ok = sum(1 for iv in cp.invariants if iv.passed)
        print(f"   ┌─ {mark} [{cp.cp_id}] {cp.name}  "
              f"(불변식 {ok}/{len(cp.invariants)} · {cp.elapsed_ms:.0f}ms)")
        for iv in cp.invariants:
            m = "✓" if iv.passed else "✗"
            detail = f"{iv.actual}" if iv.passed else f"{iv.actual}  (기대: {iv.expected})"
            print(f"   │   {m} {iv.name}: {detail}")
        if cp.inputs or cp.outputs:
            io = []
            if cp.inputs:
                io.append("IN " + ", ".join(f"{k}={v}" for k, v in cp.inputs.items()))
            if cp.outputs:
                io.append("OUT " + ", ".join(f"{k}={v}" for k, v in cp.outputs.items()))
            print(f"   └─ {' | '.join(io)}")
        else:
            print("   └─")

    def print_summary(self, line: str = "-" * 88) -> None:
        if not self.enabled or not self.checkpoints:
            return
        print(line)
        print(" 체크포인트 요약")
        print(line)
        print(f" {'ID':<7} {'스테이지':<9} {'체크포인트':<34} {'불변식':>8}  판정")
        for cp in self.checkpoints:
            ok = sum(1 for iv in cp.invariants if iv.passed)
            mark = "✅ PASS" if cp.passed else "❌ FAIL"
            print(f" {cp.cp_id:<7} {cp.stage:<9} {cp.name[:32]:<34} {ok:>3}/{len(cp.invariants):<4} {mark}")
        s = self.summary()
        print(line)
        print(f" 체크포인트 {s['passed']}/{s['total']} 통과 | "
              f"불변식 {s['invariants_passed']}/{s['invariants_total']} 통과")
        if s["failed_details"]:
            print(" 🚨 실패한 불변식:")
            for d in s["failed_details"]:
                print(f"    • [{d['cp_id']}] {d['name']}: {d['actual']} (기대: {d['expected']})")

    # ── 집계 ────────────────────────────────────────────────────────
    def summary(self) -> dict:
        total_inv = sum(len(cp.invariants) for cp in self.checkpoints)
        passed_inv = sum(1 for cp in self.checkpoints for iv in cp.invariants if iv.passed)
        failed = [
            {"cp_id": cp.cp_id, "name": iv.name, "expected": iv.expected, "actual": iv.actual}
            for cp in self.checkpoints for iv in cp.failed_invariants
        ]
        return {
            "total": len(self.checkpoints),
            "passed": sum(1 for cp in self.checkpoints if cp.passed),
            "failed": sum(1 for cp in self.checkpoints if not cp.passed),
            "invariants_total": total_inv,
            "invariants_passed": passed_inv,
            "all_passed": all(cp.passed for cp in self.checkpoints) if self.checkpoints else True,
            "failed_details": failed,
        }

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "summary": self.summary(),
            "checkpoints": [cp.to_dict() for cp in self.checkpoints],
        }
