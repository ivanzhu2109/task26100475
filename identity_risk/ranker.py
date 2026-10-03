"""身份风险排名库：进程内状态，由上层直接调用。"""

from __future__ import annotations

import heapq
from bisect import bisect_right, insort
from typing import Iterable, Optional

SECONDS_PER_DAY = 86400
DORMANCY_WINDOW_SECONDS = 30 * SECONDS_PER_DAY
DRIFT_WINDOW_SECONDS = 30 * SECONDS_PER_DAY

MAX_ENVIRONMENTS = 25
PERMISSION_SCORE_FACTOR = 35.0
DORMANCY_SCORE = 20.0
DRIFT_SCORE_PER_EVENT = 2.0
DRIFT_SCORE_CAP = 20.0

RESOURCE_CATEGORIES = ("Compute", "Storage", "Database", "IAM", "Networking")
PERMISSIONS = ("Read", "Write", "Delete", "Admin", "Network Access")

# 一项授权：(环境, 资源类别, 权限)
Authorization = tuple[str, str, str]


class IdentityRiskRanker:
    """维护身份授权、活动时间与漂移事件，支持风险 Top-N 查询。

    排名堆中的分数只在 ``self._now`` 时刻有效；时间前进时整体重算，
    同一时刻内的写入只增量更新对应身份的堆条目（懒删除）。
    """

    def __init__(self) -> None:
        self._now: Optional[int] = None
        # identity -> [env_count, auth_count, last_activity(可为 None)]
        self._profiles: dict[str, list] = {}
        # identity -> 未过期漂移事件发生时间的升序列表（允许重复）
        self._drift: dict[str, list[int]] = {}
        # identity -> 在 self._now 时刻的精确总分
        self._scores: dict[str, float] = {}
        # (-score, identity_id) 最小堆；过期条目在弹出时丢弃
        self._heap: list[tuple[float, str]] = []

    # ---- 内部 ----

    def _advance(self, now: int) -> None:
        if self._now is not None:
            if now < self._now:
                raise ValueError("now 必须非递减")
            if now == self._now:
                return
        cutoff = now - DRIFT_WINDOW_SECONDS
        for identity_id, events in self._drift.items():
            expired = bisect_right(events, cutoff)
            if expired:
                del events[:expired]
        self._now = now
        self._rebuild()

    def _score_at_now(self, identity_id: str) -> float:
        env_count, auth_count, last_activity = self._profiles[identity_id]
        score = float(env_count)
        if auth_count:
            score += PERMISSION_SCORE_FACTOR * auth_count / (MAX_ENVIRONMENTS * env_count)
        if last_activity is not None and self._now - last_activity > DORMANCY_WINDOW_SECONDS:
            score += DORMANCY_SCORE
        events = self._drift.get(identity_id)
        if events:
            score += min(DRIFT_SCORE_CAP, DRIFT_SCORE_PER_EVENT * len(events))
        return score

    def _push(self, identity_id: str) -> None:
        score = self._score_at_now(identity_id)
        self._scores[identity_id] = score
        heapq.heappush(self._heap, (-score, identity_id))
        # 懒删除会让堆膨胀，超过活条目两倍时重建以约束内存
        if len(self._heap) > 2 * len(self._scores) + 64:
            self._rebuild()

    def _rebuild(self) -> None:
        self._scores = {i: self._score_at_now(i) for i in self._profiles}
        self._heap = [(-s, i) for i, s in self._scores.items()]
        heapq.heapify(self._heap)

    # ---- 业务操作 ----

    def upsert_identity(
        self,
        identity_id: str,
        authorizations: Iterable[Authorization],
        last_activity: int,
        now: int,
    ) -> None:
        """写入或覆盖一个身份的完整授权及最后活动时间；不清除漂移事件。"""
        self._advance(now)
        grants = set(authorizations)
        env_count = len({env for env, _, _ in grants})
        self._profiles[identity_id] = [env_count, len(grants), last_activity]
        self._push(identity_id)

    def append_drift_event(self, identity_id: str, occurred_at: int, now: int) -> None:
        """追加一次漂移事件，按发生时间计入统计，允许乱序补录。"""
        self._advance(now)
        if identity_id not in self._profiles:
            self._profiles[identity_id] = [0, 0, None]
        # 已过期的事件永远不会再计入（now 非递减），直接丢弃
        if occurred_at > now - DRIFT_WINDOW_SECONDS:
            insort(self._drift.setdefault(identity_id, []), occurred_at)
        self._push(identity_id)

    def top_identities(
        self, now: int, limit: int = 10
    ) -> list[tuple[str, float]]:
        """返回风险最高的前 limit 个身份及精确分数，分数降序、并列按标识字典序。"""
        self._advance(now)
        picked: list[tuple[float, str]] = []
        seen: set[str] = set()
        while self._heap and len(picked) < limit:
            neg_score, identity_id = heapq.heappop(self._heap)
            # 同一身份可能有多条同分堆条目，重复条目直接丢弃
            if identity_id in seen:
                continue
            if self._scores.get(identity_id) == -neg_score:
                seen.add(identity_id)
                picked.append((neg_score, identity_id))
        for entry in picked:
            heapq.heappush(self._heap, entry)
        return [(identity_id, -neg_score) for neg_score, identity_id in picked]
