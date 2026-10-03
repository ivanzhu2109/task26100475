"""规模与资源验收测试。

规模：100000 个身份、合计 1000000 项当前授权、最近 30 天内 1000000 条漂移事件。
- 进程峰值内存不超过 512 MiB；
- 同一业务时刻连续 10000 次单身份资料覆盖 + 前 10 名查询，总耗时不超过 10 秒；
- 时间跳跃后的首个查询直接返回当前排名；
- 累计大量覆盖与追加后内存保持有界（过期事件被清理）。
"""

import gc
import resource
import sys
import time
import tracemalloc

from identity_risk import IdentityRiskRanker, SECONDS_PER_DAY

T0 = 1_700_000_000
DAY = SECONDS_PER_DAY
WINDOW = 30 * DAY

IDENTITIES = 100_000
GRANTS_PER_IDENTITY = 10      # 合计 1_000_000 项授权
EVENTS_PER_IDENTITY = 10      # 合计 1_000_000 条窗口内漂移事件
MIB = 1024 * 1024


def peak_rss_bytes():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS 返回字节，Linux 返回 KiB
    return peak if sys.platform == "darwin" else peak * 1024


def make_grants(seed):
    categories = ["Compute", "Storage", "Database", "IAM", "Networking"]
    permissions = ["Read", "Write", "Delete", "Admin", "Network Access"]
    combos = [(c, p) for c in categories for p in permissions]
    grants = []
    for i in range(GRANTS_PER_IDENTITY):
        c, p = combos[(seed + i) % len(combos)]
        grants.append((f"env-{(seed + i) % 7}", c, p))
    return grants


def build_ranker(with_drift):
    r = IdentityRiskRanker()
    for i in range(IDENTITIES):
        r.upsert_identity(T0, f"identity-{i:06d}", make_grants(i), T0)
    if with_drift:
        now = T0 + EVENTS_PER_IDENTITY  # 所有追加使用同一非递减时刻
        for i in range(IDENTITIES):
            name = f"identity-{i:06d}"
            for j in range(EVENTS_PER_IDENTITY):
                r.add_drift_event(now, name, T0 + j)
    return r


class TestScale:
    def test_memory_within_512_mib_at_full_scale(self):
        r = build_ranker(with_drift=True)
        gc.collect()
        # 触发一次含全量刷新的查询，计入峰值
        top = r.top_identities(T0 + 100)
        assert len(top) == 10
        gc.collect()
        peak = peak_rss_bytes()
        print(f"\npeak RSS = {peak / MIB:.0f} MiB")
        assert peak < 512 * MIB

    def test_expired_events_are_reclaimed(self):
        tracemalloc.start()
        r = build_ranker(with_drift=True)
        r.top_identities(T0 + EVENTS_PER_IDENTITY + 1)  # 预热：结构进入刷新后形态
        gc.collect()
        before = tracemalloc.take_snapshot()
        # 时间跳出窗口：100 万条事件全部过期
        top = r.top_identities(T0 + EVENTS_PER_IDENTITY + WINDOW + 100)
        assert len(top) == 10
        gc.collect()
        after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        freed = sum(s.size_diff for s in after.compare_to(before, "filename"))
        print(f"\ntracemalloc diff after expiry: {freed / MIB:.1f} MiB")
        assert not r._drift  # 过期事件全部清除
        assert freed < 0     # 内存只减不增


class TestThroughput:
    def test_10000_upserts_with_top10_queries_under_10_seconds(self):
        r = build_ranker(with_drift=False)
        now = T0 + 1000
        r.top_identities(now)  # 推进内部时刻，预热

        start = time.perf_counter()
        for i in range(10_000):
            r.upsert_identity(now, f"identity-{i:06d}", make_grants(i + 1), now)
            top = r.top_identities(now)
            assert len(top) == 10
        elapsed = time.perf_counter() - start
        print(f"\n10000 upsert+query: {elapsed:.2f}s")
        assert elapsed < 10.0

    def test_first_query_after_time_jump_is_current(self):
        r = build_ranker(with_drift=False)
        now = T0 + 1000
        r.top_identities(now)
        # 时间跳跃 40 天（无任何写入），首个查询必须直接反映休眠后的排名
        later = now + 40 * DAY
        start = time.perf_counter()
        top = r.top_identities(later)
        elapsed = time.perf_counter() - start
        print(f"\nfirst query after 40d jump: {elapsed:.3f}s")
        assert len(top) == 10
        assert all(score >= 20.0 for _, score in top)  # 全部计入休眠项
        assert elapsed < 10.0


class TestCumulativeOperations:
    def test_memory_bounded_over_many_overwrites_and_appends(self):
        r = IdentityRiskRanker()
        identities = [f"churn-{i:05d}" for i in range(1000)]
        for i, name in enumerate(identities):
            r.upsert_identity(T0, name, make_grants(i), T0)
        gc.collect()
        tracemalloc.start()
        baseline = tracemalloc.take_snapshot()

        now = T0
        for i in range(300_000):
            if i % 1000 == 0:
                now += 60  # 时间缓慢前进，旧事件不断过期
            name = identities[i % len(identities)]
            if i % 2 == 0:
                r.upsert_identity(now, name, make_grants(i), now)
            else:
                r.add_drift_event(now, name, now)
        gc.collect()
        after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        growth = sum(s.size_diff for s in after.compare_to(baseline, "filename"))
        stored_events = sum(len(events) for events in r._drift.values())
        print(f"\ngrowth after 300k ops: {growth / MIB:.1f} MiB, "
              f"stored events: {stored_events}")
        assert growth < 100 * MIB
        # 窗口内最多 1000 身份 * (30 天 / 60 秒) 条事件
        assert stored_events <= 1000 * (WINDOW // 60 + 1)
