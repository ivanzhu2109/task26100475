import time

from identity_risk import IdentityRiskRanker, RESOURCE_CATEGORIES, PERMISSIONS

DAY = 86400
WINDOW = 30 * DAY
T0 = 1_700_000_000


def make_auths(env, count):
    """生成同一环境内 count 个互不相同的 (环境, 类别, 权限) 组合。"""
    combos = [(env, c, p) for c in RESOURCE_CATEGORIES for p in PERMISSIONS]
    assert count <= len(combos)
    return combos[:count]


def test_auth_change_drops_score_and_updates_ranking():
    r = IdentityRiskRanker()
    # 一个环境 25 项授权 -> 1 + 35 = 36
    r.upsert_identity("target", make_auths("env-a", 25), last_activity=T0, now=T0)
    # 参照身份：2 环境 30 项授权 -> 2 + 35*30/50 = 23
    r.upsert_identity("ref", make_auths("env-a2", 25) + make_auths("env-b2", 5),
                      last_activity=T0, now=T0)
    top = r.top_identities(now=T0)
    assert top[0] == ("target", 36.0)
    assert top[1] == ("ref", 23.0)

    # 两个环境共 26 项授权 -> 2 + 35*26/50 = 20.2，立即影响排名
    r.upsert_identity("target", make_auths("env-a", 25) + make_auths("env-b", 1),
                      last_activity=T0, now=T0)
    top = r.top_identities(now=T0)
    assert top[0] == ("ref", 23.0)
    assert top[1] == ("target", 20.2)


def test_drift_window_and_dormancy_boundary():
    r = IdentityRiskRanker()
    # 11 条事件：t+1 一条、t+2 一条、t+3 九条
    r.upsert_identity("d", make_auths("env-a", 25), last_activity=T0, now=T0)
    r.append_drift_event("d", occurred_at=T0 + 1, now=T0 + 3)
    r.append_drift_event("d", occurred_at=T0 + 2, now=T0 + 3)
    for _ in range(9):
        r.append_drift_event("d", occurred_at=T0 + 3, now=T0 + 3)
    # 11 条在窗内，漂移项封顶 20：36 + 20 = 56
    assert r.top_identities(now=T0 + 3) == [("d", 56.0)]

    # 恰好在 30 天窗口边界的事件已过期：11 -> 10，漂移项仍为 20
    # （刷新最后活动时间以隔离休眠项）
    now1 = T0 + 1 + WINDOW
    r.upsert_identity("d", make_auths("env-a", 25), last_activity=now1, now=now1)
    assert r.top_identities(now=now1) == [("d", 56.0)]
    # 再过期一条：10 -> 9，漂移项降为 18
    now2 = T0 + 2 + WINDOW
    r.upsert_identity("d", make_auths("env-a", 25), last_activity=now2, now=now2)
    assert r.top_identities(now=now2) == [("d", 54.0)]

    # 距最后活动恰好 30 天不计休眠
    r2 = IdentityRiskRanker()
    r2.upsert_identity("x", make_auths("env-a", 25), last_activity=T0, now=T0)
    assert r2.top_identities(now=T0 + WINDOW) == [("x", 36.0)]
    # 再过 1 秒才计入休眠
    assert r2.top_identities(now=T0 + WINDOW + 1) == [("x", 56.0)]


def test_interleaved_backfill_correction_and_ties():
    r = IdentityRiskRanker()
    # 并列：两个身份授权完全相同，精确分数相等，按标识字典序
    r.upsert_identity("id-b", make_auths("env-a", 25) + make_auths("env-b", 1),
                      last_activity=T0, now=T0)
    r.upsert_identity("id-a", make_auths("env-c", 25) + make_auths("env-d", 1),
                      last_activity=T0, now=T0)
    assert r.top_identities(now=T0) == [("id-a", 20.2), ("id-b", 20.2)]

    # 乱序补录：发生时间早于已录入事件，仍按发生时间计入
    r.append_drift_event("id-b", occurred_at=T0 - 100, now=T0)
    assert r.top_identities(now=T0) == [("id-b", 22.2), ("id-a", 20.2)]

    # 补录一条已经过期的事件：不计入
    r.append_drift_event("id-a", occurred_at=T0 - WINDOW - 5, now=T0)
    assert r.top_identities(now=T0) == [("id-b", 22.2), ("id-a", 20.2)]

    # 活动时间纠正为更晚：休眠消失；再纠正为更早：休眠出现
    r.upsert_identity("id-a", make_auths("env-c", 25) + make_auths("env-d", 1),
                      last_activity=T0 + WINDOW, now=T0 + WINDOW + 1)
    r.upsert_identity("id-b", make_auths("env-a", 25) + make_auths("env-b", 1),
                      last_activity=T0 + WINDOW, now=T0 + WINDOW + 1)
    # id-b 的漂移事件（T0-100）此刻已过期
    assert r.top_identities(now=T0 + WINDOW + 1) == [("id-a", 20.2), ("id-b", 20.2)]
    r.upsert_identity("id-a", make_auths("env-c", 25) + make_auths("env-d", 1),
                      last_activity=T0, now=T0 + WINDOW + 1)
    assert r.top_identities(now=T0 + WINDOW + 1) == [("id-a", 40.2), ("id-b", 20.2)]

    # 覆盖资料不清除漂移事件：给 id-b 补一条窗内事件后覆盖资料，漂移仍计入
    r.append_drift_event("id-b", occurred_at=T0 + WINDOW, now=T0 + WINDOW + 1)
    r.upsert_identity("id-b", make_auths("env-a", 10),
                      last_activity=T0 + WINDOW, now=T0 + WINDOW + 1)
    # id-b: 1 + 35*10/25 = 15，漂移 2 -> 17
    assert r.top_identities(now=T0 + WINDOW + 1) == [("id-a", 40.2), ("id-b", 17.0)]


def test_no_auth_identity_ranked_and_partial_results():
    r = IdentityRiskRanker()
    r.append_drift_event("ghost", occurred_at=T0, now=T0)
    # 无授权身份仍参与排名：0 + 漂移 2
    assert r.top_identities(now=T0) == [("ghost", 2.0)]
    # 不足 10 个全部返回
    r.upsert_identity("a", make_auths("env-a", 1), last_activity=T0, now=T0)
    assert r.top_identities(now=T0) == [("a", 2.4), ("ghost", 2.0)]


def test_events_beyond_cap_affect_later_expiry():
    r = IdentityRiskRanker()
    r.upsert_identity("e", [], last_activity=T0 + WINDOW + 10, now=T0)
    # 12 条同时刻事件分别计数；1 条更早
    r.append_drift_event("e", occurred_at=T0, now=T0)
    for _ in range(12):
        r.append_drift_event("e", occurred_at=T0 + 5, now=T0 + 5)
    assert r.top_identities(now=T0 + 5) == [("e", 20.0)]
    # 最早一条过期后仍有 12 条，超过 10 条的部分使漂移项保持封顶
    assert r.top_identities(now=T0 + WINDOW + 1) == [("e", 20.0)]


def test_time_jump_query_returns_current_ranking():
    r = IdentityRiskRanker()
    r.upsert_identity("p", make_auths("env-a", 25), last_activity=T0, now=T0)
    for _ in range(5):
        r.append_drift_event("p", occurred_at=T0, now=T0)
    assert r.top_identities(now=T0) == [("p", 46.0)]
    # 长时间无写入后直接查询：漂移过期、休眠生效，首个查询即为当前结果
    assert r.top_identities(now=T0 + 100 * DAY) == [("p", 56.0)]


def test_now_must_be_non_decreasing():
    r = IdentityRiskRanker()
    r.upsert_identity("a", [], last_activity=T0, now=T0 + 10)
    try:
        r.top_identities(now=T0)
    except ValueError:
        pass
    else:
        raise AssertionError("应拒绝回退的 now")


def test_heap_stays_bounded_under_churn():
    r = IdentityRiskRanker()
    for i in range(20000):
        r.upsert_identity(f"id-{i % 1000}", make_auths("env-a", i % 25 + 1),
                          last_activity=T0, now=T0)
    assert len(r._heap) <= 2 * len(r._scores) + 64


def test_perf_10k_upsert_query_cycles():
    r = IdentityRiskRanker()
    n_identities = 100_000
    auths = make_auths("env-a", 10)  # 合计 1_000_000 项授权
    for i in range(n_identities):
        r.upsert_identity(f"id-{i:06d}", auths, last_activity=T0, now=T0)

    start = time.perf_counter()
    for i in range(10_000):
        r.upsert_identity(f"id-{i:06d}", make_auths("env-a", 10) + make_auths("env-b", 1),
                          last_activity=T0, now=T0)
        r.top_identities(now=T0)
    elapsed = time.perf_counter() - start
    assert elapsed < 10.0, f"10000 次覆盖+查询耗时 {elapsed:.2f}s"
