"""AuditClient — 앱이 쓰는 감사 SDK 진입점."""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from . import context
from .event import actor_from_user, build_event, normalize
from .sink import AuditSink, JsonlSink

DEFAULT_FILENAME = "audit_events.jsonl"


class AuditClient:
    """서비스 하나당 하나씩 두는 감사 기록 클라이언트.

        audit = AuditClient(service="rag-service", out_dir=BASE_DIR / "audit_out")
        audit.record(action="rag_query", asset="vector_index",
                     result="success", user=current_user, purpose=question)
    """

    def __init__(
        self,
        service: str,
        out_dir=None,
        filename: str = DEFAULT_FILENAME,
        sink: Optional[AuditSink] = None,
    ):
        self.service = service
        if sink is not None:
            self.sink = sink
            self.path = None
        else:
            if out_dir is None:
                raise ValueError("out_dir 또는 sink 중 하나는 지정해야 합니다.")
            self.path = Path(out_dir) / filename
            self.sink = JsonlSink(self.path)

    # ------------------------------------------------------------- 기록
    def record(
        self,
        action: str,
        asset: str,
        result: str,
        actor: str = "",
        role: str = "",
        purpose: str = "",
        record_id: str = "",
        source_ip: str = "",
        user: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """감사 이벤트 한 건을 기록한다.

        `user` 를 주면 로그인 사용자 dict 에서 actor/role 을 꺼내 쓴다.
        record_id / source_ip 를 생략하면 현재 요청 컨텍스트에서 채운다.
        """
        user_actor, user_role = actor_from_user(user)
        event = build_event(
            action=action,
            asset=asset,
            result=result,
            service=self.service,
            actor=actor or user_actor or context.get("actor"),
            role=role or user_role or context.get("role"),
            purpose=purpose,
            record_id=record_id or self._next_record_id(),
            source_ip=source_ip or context.get("source_ip"),
        )
        self.sink.write(normalize(event))
        # 요청당 감사 이벤트는 한 건이다. 미들웨어가 같은 요청을 중복 기록하지
        # 않도록 표시한다 (record_id 중복 방지).
        context.mark_recorded()
        return event

    def _next_record_id(self) -> str:
        """요청 안에서 감사 이벤트가 여러 건 나올 때 record_id 충돌을 막는다.

        한 요청이 여러 단계를 거치면(문서 임베딩 → 검색 → LLM 호출 → 응답) 단계마다
        기록할 것이 있다. 전부 같은 record_id 를 쓰면 추적성이 훼손되고
        (감사 점검 항목 AUD-008 record_id 중복), 완전히 다른 id 를 쓰면 어느 요청에서
        나온 단계인지 이어붙일 수 없다.

        그래서 첫 건은 `req-abc12345`, 이후는 `req-abc12345.2`, `.3` … 으로 매긴다.
        접두사가 같아 한 요청으로 묶이고, 값은 서로 다르다.
        """
        base = context.get("record_id")
        if not base:
            return ""
        seq = context.next_sequence()
        return base if seq <= 1 else "{}.{}".format(base, seq)

    # ------------------------------------------------------------- 컨텍스트
    def set_actor(self, actor: str, role: str = "") -> None:
        """인증이 끝난 시점에 호출한다. 이후 이 요청의 모든 기록에 반영된다."""
        context.set_actor(actor, role)

    def set_actor_hint(self, actor: str, role: str = "unauthenticated") -> None:
        """아직 인증 전이지만 '누가 시도했는지'를 남겨야 할 때 쓴다.

        로그인 rate limit 은 인증보다 먼저 걸린다. 미리 채워두지 않으면 무차별
        대입으로 차단된 429 이벤트에 IP 만 남고 시도한 계정명이 사라진다.
        """
        context.set_actor(actor, role)

    # ------------------------------------------------------------- 적재 파일
    def read_all(self):
        """적재된 이벤트와 깨진 줄 수를 반환한다."""
        return self.sink.read_all()

    def rotate(self, suffix: str = "") -> Optional[Path]:
        """적재 파일을 보관 파일로 옮기고 새 적재를 시작한다."""
        if self.path is None or not self.path.exists():
            return None
        suffix = suffix or datetime.now().strftime("%Y%m%d_%H%M%S")
        archive = self.path.with_name(
            "{}_{}{}".format(self.path.stem, suffix, self.path.suffix)
        )
        shutil.move(str(self.path), str(archive))
        return archive
