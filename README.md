# task26100475

身份风险排名库：纯进程内状态，无接口层，由上层直接调用。

## 用法

```python
from identity_risk import IdentityRiskRanker

ranker = IdentityRiskRanker()

# 写入或覆盖一个身份的完整授权及最后活动时间（不清除漂移事件）
ranker.upsert_identity(
    "alice",
    authorizations=[("env-1", "Compute", "Admin"), ("env-1", "Storage", "Read")],
    last_activity=1_700_000_000,
    now=1_700_000_100,
)

# 追加一次漂移事件（按发生时间计入，允许乱序补录）
ranker.append_drift_event("alice", occurred_at=1_700_000_050, now=1_700_000_100)

# 查询风险最高的前 10 个身份及精确分数
top = ranker.top_identities(now=1_700_000_100)  # [("alice", 3.4), ...]
```

## 规则摘要

- 总分 100 = 环境项（已授权环境数）+ 权限项（35 × 授权总数 / (25 × 已授权环境数)，无授权为 0）
  + 休眠项（最后活动距今严格超过 30 天为 20）+ 漂移项（最近 30 天事件数 × 2，封顶 20）。
- 时间为 UTC 整数秒，1 天 = 86400 秒；所有调用的 `now` 必须非递减。
- 排名按分数降序，精确相等时按身份标识字典序升序，不舍入。

## 测试

```bash
python3 -m pytest tests/ -q
```
