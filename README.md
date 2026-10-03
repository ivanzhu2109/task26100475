# identity-risk

多云环境身份风险排名库。纯进程内存实现，上层直接调用，无接口层、无持久化。

## 用法

```python
from identity_risk import IdentityRiskRanker

ranker = IdentityRiskRanker()

# 写入或覆盖一个身份的完整授权及最后活动时间（不清除其漂移事件）
ranker.upsert_identity(
    now=1_700_000_000,
    identity="alice",
    grants=[("prod", "Compute", "Read"), ("prod", "Storage", "Admin")],
    last_activity=1_700_000_000,
)

# 追加一次漂移事件（按发生时间计入，允许乱序补录）
ranker.add_drift_event(now=1_700_000_000, identity="alice", event_time=1_699_999_000)

# 查询风险最高的前 10 个身份，返回 [(identity, score), ...]
top = ranker.top_identities(now=1_700_000_000)
```

## 规则摘要

- 时间为 UTC 整数秒，1 天 = 86400 秒；所有调用的 `now` 必须非递减。
- 风险满分 100：环境项（已授权环境数）+ 权限项（35 × 授权总数 ÷ (25 × 已授权环境数)，无授权为 0）
  + 休眠项（最后活动距今严格超过 30 天为 20）+ 漂移项（最近 30 天事件数 × 2，封顶 20）。
- 恰好 30 天前的事件已过期；恰好 30 天未活动不算休眠。
- 排名按精确分数降序，相等时按身份标识字典序升序，不舍入。
- 每次查询都以调用时刻为准，时间跳跃后的首个查询直接返回当前排名。

## 测试

```bash
python3 -m pytest tests/ -q
```

`tests/test_ranker.py` 为功能验收；`tests/test_performance.py` 为规模与资源验收
（10 万身份 / 100 万授权 / 100 万窗口内漂移事件，峰值内存 < 512 MiB，
同一时刻 1 万次覆盖 + 查询 < 10 秒）。
