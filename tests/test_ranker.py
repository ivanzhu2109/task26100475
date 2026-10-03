"""IdentityRiskRanker 功能验收测试。"""

import pytest

from identity_risk import IdentityRiskRanker, SECONDS_PER_DAY, WINDOW_SECONDS

T0 = 1_700_000_000
DAY = SECONDS_PER_DAY


def grants_for(env, count):
    """生成指定环境内 count 项互不相同的授权（类别 × 权限共 25 种组合）。"""
    categories = ["Compute", "Storage", "Database", "IAM", "Networking"]
    permissions = ["Read", "Write", "Delete", "Admin", "Network Access"]
    combos = [(env, c, p) for c in categories for p in permissions]
    assert count <= len(combos)
    return combos[:count]


def fixed_score(env_count, total):
    return env_count + (35.0 * total / (25.0 * env_count) if env_count else 0.0)


class TestAuthorizationScoring:
    def test_one_env_25_grants_scores_36(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", grants_for("env1", 25), T0)
        assert r.top_identities(T0) == [("alice", 36.0)]

    def test_two_envs_26_grants_scores_20_2_and_reranks(self):
        r = IdentityRiskRanker()
        # bob 固定 30 分：2 个环境、40 项授权
        r.upsert_identity(T0, "bob", grants_for("envA", 25) + grants_for("envB", 15), T0)
        assert r.top_identities(T0)[0] == ("bob", 30.0)

        r.upsert_identity(T0, "alice", grants_for("env1", 25), T0)
        assert r.top_identities(T0) == [("alice", 36.0), ("bob", 30.0)]

        # 覆盖为两个环境共 26 项授权：36 -> 20.2，立即跌到 bob 之后
        r.upsert_identity(T0, "alice", grants_for("env1", 25) + grants_for("env2", 1), T0)
        top = r.top_identities(T0)
        assert top == [("bob", 30.0), ("alice", fixed_score(2, 26))]
        assert top[1][1] == pytest.approx(20.2)

    def test_duplicate_grant_combination_counts_once_per_env(self):
        r = IdentityRiskRanker()
        grants = [("e1", "Compute", "Read"), ("e1", "Compute", "Read"),
                  ("e2", "Compute", "Read")]
        r.upsert_identity(T0, "alice", grants, T0)
        # e1 的重复组合只算一项，共 2 个环境、2 项授权
        assert r.top_identities(T0) == [("alice", fixed_score(2, 2))]

    def test_same_combination_in_different_envs_counts_separately(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [("e1", "Compute", "Read")], T0)
        r.upsert_identity(T0, "bob", [("e1", "Compute", "Read"),
                                      ("e2", "Compute", "Read")], T0)
        top = dict(r.top_identities(T0))
        assert top["alice"] == fixed_score(1, 1)
        assert top["bob"] == fixed_score(2, 2)

    def test_upsert_does_not_clear_drift_events(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", grants_for("e1", 1), T0)
        r.add_drift_event(T0, "alice", T0)
        r.upsert_identity(T0, "alice", grants_for("e1", 2), T0)
        assert r.top_identities(T0) == [("alice", fixed_score(1, 2) + 2.0)]

    def test_identity_without_grants_participates(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [], T0)
        assert r.top_identities(T0) == [("alice", 0.0)]

    def test_drift_only_identity_participates(self):
        r = IdentityRiskRanker()
        r.add_drift_event(T0, "ghost", T0)
        assert r.top_identities(T0) == [("ghost", 2.0)]


class TestDormancyAndDriftWindows:
    def test_exactly_30_days_inactive_is_not_dormant_then_one_more_second_is(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [], T0)
        assert r.top_identities(T0 + WINDOW_SECONDS) == [("alice", 0.0)]
        assert r.top_identities(T0 + WINDOW_SECONDS + 1) == [("alice", 20.0)]

    def test_drift_counts_11_10_9_give_20_20_18(self):
        r = IdentityRiskRanker()
        # 1 条在 T0+1，1 条在 T0+2，9 条在 T0+3，共 11 条
        r.add_drift_event(T0 + 1, "alice", T0 + 1)
        r.add_drift_event(T0 + 2, "alice", T0 + 2)
        for _ in range(9):
            r.add_drift_event(T0 + 3, "alice", T0 + 3)

        # 每个检查点都把最后活动时间刷新为当前时刻，隔离出纯漂移项
        def drift_score(now):
            r.upsert_identity(now, "alice", [], now)
            return r.top_identities(now)[0][1]

        # 11 条在窗口内：11*2=22，封顶 20
        assert drift_score(T0 + 3) == 20.0
        # 恰好 30 天后 T0+1 的事件过期，剩 10 条：10*2=20
        assert drift_score(T0 + 1 + WINDOW_SECONDS) == 20.0
        # 再过 1 秒 T0+2 的事件也过期，剩 9 条：9*2=18
        assert drift_score(T0 + 2 + WINDOW_SECONDS) == 18.0

    def test_event_exactly_30_days_old_is_expired(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [], T0)
        r.add_drift_event(T0, "alice", T0)
        assert r.top_identities(T0 + WINDOW_SECONDS - 1) == [("alice", 2.0)]
        assert r.top_identities(T0 + WINDOW_SECONDS) == [("alice", 0.0)]

    def test_same_timestamp_events_count_individually(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [], T0)
        for _ in range(3):
            r.add_drift_event(T0, "alice", T0)
        assert r.top_identities(T0) == [("alice", 6.0)]

    def test_first_query_after_time_jump_reflects_current_rules(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", grants_for("e1", 25), T0)  # 36 固定
        r.upsert_identity(T0, "bob", grants_for("e1", 1), T0)     # 2.4 固定
        r.add_drift_event(T0, "bob", T0)                          # +2，共 4.4
        # 长时间无任何写入后直接查询：两者都休眠 +20，bob 漂移过期
        top = r.top_identities(T0 + 40 * DAY)
        assert top == [("alice", 56.0), ("bob", fixed_score(1, 1) + 20.0)]


class TestBackfillCorrectionAndTies:
    def test_out_of_order_backfill_including_expired_event(self):
        r = IdentityRiskRanker()
        now = T0 + 40 * DAY
        r.upsert_identity(now, "alice", [], now)
        # 乱序补录：先近后远，再补一条已经过期的事件
        r.add_drift_event(now, "alice", now - 1)
        r.add_drift_event(now, "alice", now - 5 * DAY)
        r.add_drift_event(now, "alice", T0)  # 40 天前，已过期，不计入
        assert r.top_identities(now) == [("alice", 4.0)]

    def test_last_activity_can_be_corrected_earlier_and_later(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [], T0)
        now = T0 + 40 * DAY
        assert r.top_identities(now) == [("alice", 20.0)]  # 休眠
        # 纠正为更晚：不再休眠
        r.upsert_identity(now, "alice", [], now - 1 * DAY)
        assert r.top_identities(now) == [("alice", 0.0)]
        # 再纠正为更早：重新休眠
        r.upsert_identity(now, "alice", [], now - 31 * DAY)
        assert r.top_identities(now) == [("alice", 20.0)]

    def test_exact_tie_breaks_by_identity_ascending(self):
        r = IdentityRiskRanker()
        grants = grants_for("e1", 25) + grants_for("e2", 1)
        r.upsert_identity(T0, "carol", grants, T0)
        r.upsert_identity(T0, "alice", grants, T0)
        r.upsert_identity(T0, "bob", grants, T0)
        scores = r.top_identities(T0)
        assert [name for name, _ in scores] == ["alice", "bob", "carol"]
        assert all(score == fixed_score(2, 26) for _, score in scores)

    def test_interleaved_operations_keep_exact_ranking(self):
        r = IdentityRiskRanker()
        g25 = grants_for("e1", 25)           # 固定 36
        g26 = grants_for("e1", 25) + grants_for("e2", 1)  # 固定 20.2

        r.upsert_identity(T0, "alice", g25, T0)
        r.upsert_identity(T0, "bob", g26, T0)
        assert r.top_identities(T0) == [("alice", 36.0), ("bob", fixed_score(2, 26))]

        # bob 补 10 条漂移：20.2 + 20 = 40.2，超过 alice
        for i in range(10):
            r.add_drift_event(T0 + 1 + i, "bob", T0 + 1 + i)
        now = T0 + 11
        assert r.top_identities(now) == [("bob", fixed_score(2, 26) + 20.0),
                                         ("alice", 36.0)]

        # alice 覆盖资料（漂移清零不适用，此处无漂移）并把活动时间改早 -> 休眠
        r.upsert_identity(now, "alice", g26, now - 31 * DAY)
        assert r.top_identities(now) == [("alice", fixed_score(2, 26) + 20.0),
                                         ("bob", fixed_score(2, 26) + 20.0)]
        # 两者精确同分，按字典序 alice 在前

        # 时间推进到 bob 最早一条漂移恰好过期，bob 剩 9 条 -> 18；
        # 此时两者最后活动都超过 30 天，均休眠 +20
        later = T0 + 1 + WINDOW_SECONDS
        top = r.top_identities(later)
        assert top == [("bob", fixed_score(2, 26) + 18.0 + 20.0),
                       ("alice", fixed_score(2, 26) + 20.0)]


class TestQueryShape:
    def test_returns_all_when_fewer_than_limit(self):
        r = IdentityRiskRanker()
        for i in range(3):
            r.upsert_identity(T0, f"id{i}", [], T0)
        assert len(r.top_identities(T0)) == 3

    def test_limit_defaults_to_10(self):
        r = IdentityRiskRanker()
        for i in range(15):
            r.upsert_identity(T0, f"id{i:02d}", [], T0)
            r.add_drift_event(T0, f"id{i:02d}", T0)
        top = r.top_identities(T0)
        assert len(top) == 10
        assert all(score == 2.0 for _, score in top)
        assert [name for name, _ in top] == [f"id{i:02d}" for i in range(10)]

    def test_decreasing_now_rejected(self):
        r = IdentityRiskRanker()
        r.upsert_identity(T0, "alice", [], T0)
        with pytest.raises(ValueError):
            r.top_identities(T0 - 1)
