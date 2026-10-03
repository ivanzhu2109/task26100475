"""身份风险排名库（进程内存实现）。

上层直接调用 `IdentityRiskRanker`，无接口层、无持久化。
时间一律为 UTC 整数秒，1 天固定 86400 秒；所有调用的当前时刻非递减。

风险满分 100，由四项相加：
- 环境项：已授权环境数（同一环境、资源类别、权限的组合只算一项授权）。
- 权限项：35 * 授权总数 / (25 * 已授权环境数)，无授权时为 0。
- 休眠项：最后活动距今严格超过 30 天为 20，否则为 0。
- 漂移项：最近 30 天事件数 * 2，最高 20；恰好 30 天前的事件已过期。

排名按分数降序，精确相等时按身份标识字典序升序，不舍入。
"""

from __future__ import annotations

import sys
from bisect import bisect_left, bisect_right, insort
from typing import Iterable

SECONDS_PER_DAY = 86400
WINDOW_SECONDS = 30 * SECONDS_PER_DAY
MAX_ENVIRONMENTS = 25

RESOURCE_CATEGORIES = ("Compute", "Storage", "Database", "IAM", "Networking")
PERMISSIONS = ("Read", "Write", "Delete", "Admin", "Network Access")

_CATEGORY_INDEX = {name: i for i, name in enumerate(RESOURCE_CATEGORIES)}
_PERMISSION_INDEX = {name: i for i, name in enumerate(PERMISSIONS)}

ENVIRONMENT_WEIGHT = 1.0
PERMISSION_WEIGHT = 35.0
DORMANCY_WEIGHT = 20.0
DRIFT_EVENT_WEIGHT = 2.0
DRIFT_MAX_SCORE = 20.0

Grant = tuple[str, str, str]  # (environment, resource_category, permission)


class IdentityRiskRanker:
    """维护身份授权、最后活动时间与漂移事件，并提供风险前 10 查询。

    内部不变式：`_sorted` 在 `_time` 时刻有效；写操作遇到更新的时刻时
    先全量刷新到该时刻，再做增量插入，保证查询可直接取结果。
    """

    def __init__(self) -> None:
        self._time = 0
        # identity -> {environment: 25 位授权位掩码}（类别 5 类 × 权限 5 种）
        self._grants: dict[str, dict[str, int]] = {}
        # identity -> 最后活动时间（仅由 upsert 设置）
        self._last_activity: dict[str, int] = {}
        # identity -> 升序事件发生时间列表（仅保留未过期事件）
        self._drift: dict[str, list[int]] = {}
        # identity -> 环境项 + 权限项（仅随 upsert 变化）
        self._fixed: dict[str, float] = {}
        # identity -> 当前完整分数（在 _time 时刻有效），覆盖所有已知身份
        self._score: dict[str, float] = {}
        # 升序排列的 (-score, identity)，即分数降序、标识字典序升序
        self._sorted: list[tuple[float, str]] = []

    # ------------------------------------------------------------------ #
    # 业务操作                                                            #
    # ------------------------------------------------------------------ #

    def upsert_identity(
        self,
        now: int,
        identity: str,
        grants: Iterable[Grant],
        last_activity: int,
    ) -> None:
        """写入或覆盖一个身份的完整授权及最后活动时间（不清除漂移事件）。"""
        self._check_now(now)
        if last_activity > now:
            raise ValueError("last_activity 不能晚于当前时刻")
        self._refresh(now)

        env_masks: dict[str, int] = {}
        for env, category, permission in grants:
            bit = 1 << (_CATEGORY_INDEX[category] * 5 + _PERMISSION_INDEX[permission])
            key = sys.intern(env)
            env_masks[key] = env_masks.get(key, 0) | bit

        env_count = len(env_masks)
        total = 0
        for mask in env_masks.values():
            total += mask.bit_count()
        fixed = float(env_count)
        if env_count:
            fixed += PERMISSION_WEIGHT * total / (MAX_ENVIRONMENTS * env_count)

        self._grants[identity] = env_masks
        self._last_activity[identity] = last_activity
        self._fixed[identity] = fixed
        self._remove_from_sorted(identity)
        score = self._current_score(identity, fixed)
        self._score[identity] = score
        insort(self._sorted, (-score, identity))

    def add_drift_event(self, now: int, identity: str, event_time: int) -> None:
        """追加一次漂移事件，按发生时间计入最近 30 天窗口。

        允许乱序补录；已经过期（不晚于 now - 30 天）的事件直接丢弃，
        因为调用时刻非递减，它们不可能再计入任何未来窗口。
        """
        self._check_now(now)
        if event_time > now:
            raise ValueError("event_time 不能晚于当前时刻")
        self._refresh(now)

        if event_time <= now - WINDOW_SECONDS:
            if identity not in self._score:
                self._register(identity)
            return

        events = self._drift.setdefault(identity, [])
        insort(events, event_time)
        if identity not in self._score:
            self._register(identity)
            return
        self._remove_from_sorted(identity)
        score = self._current_score(identity, self._fixed.get(identity, 0.0))
        self._score[identity] = score
        insort(self._sorted, (-score, identity))

    def top_identities(self, now: int, limit: int = 10) -> list[tuple[str, float]]:
        """以调用时刻为准，返回风险最高的前 limit 个身份及精确分数。"""
        self._check_now(now)
        self._refresh(now)
        return [(identity, -neg_score) for neg_score, identity in self._sorted[:limit]]

    # ------------------------------------------------------------------ #
    # 内部实现                                                            #
    # ------------------------------------------------------------------ #

    def _check_now(self, now: int) -> None:
        if now < self._time:
            raise ValueError("当前时刻必须非递减")

    def _register(self, identity: str) -> None:
        """登记一个仅由漂移事件引入的身份（无授权、无活动时间）。"""
        score = self._current_score(identity, 0.0)
        self._score[identity] = score
        insort(self._sorted, (-score, identity))

    def _current_score(self, identity: str, fixed: float) -> float:
        score = fixed
        last_activity = self._last_activity.get(identity)
        if last_activity is not None and self._time - last_activity > WINDOW_SECONDS:
            score += DORMANCY_WEIGHT
        events = self._drift.get(identity)
        if events:
            score += min(DRIFT_MAX_SCORE, DRIFT_EVENT_WEIGHT * len(events))
        return score

    def _remove_from_sorted(self, identity: str) -> None:
        old = self._score.get(identity)
        if old is None:
            return
        index = bisect_left(self._sorted, (-old, identity))
        # 分数为精确浮点，键必存在
        del self._sorted[index]

    def _refresh(self, now: int) -> None:
        """把内部状态从 `_time` 推进到 `now`（仅当 now 更大时工作）。"""
        if now == self._time:
            return
        self._time = now

        cutoff = now - WINDOW_SECONDS
        drift = self._drift
        emptied = []
        for identity, events in drift.items():
            expired = bisect_right(events, cutoff)
            if expired:
                del events[:expired]
                if not events:
                    emptied.append(identity)
        for identity in emptied:
            del drift[identity]

        score_of = self._score
        last_activity_of = self._last_activity
        fixed_of = self._fixed
        for identity in score_of:
            score_of[identity] = self._current_score(
                identity, fixed_of.get(identity, 0.0)
            )
        self._sorted = sorted((-score, identity) for identity, score in score_of.items())
