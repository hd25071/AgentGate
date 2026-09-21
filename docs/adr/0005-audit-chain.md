# ADR-0005：审计用哈希链，不用普通日志表

- 状态：已采纳
- 日期：2026-09

## 背景

"Agent 执行了生产删除"这种事，事后一定会被问三个问题：

1. 它是被允许的，还是被绕过的？
2. 谁批的？引用的是哪个动作？
3. 记录是全的，还是被人删过几条？

一张普通的事件表能回答前两个，回答不了第三个。而第三个恰恰是最关键的：
**如果审计本身可以被静默修改，那么前两个答案都不可信。**

## 决策

审计记录用哈希链串联：

```go
// internal/store/sql.go
func chainHash(prev string, rec AuditRecord) string {
    h := sha256.New()
    h.Write([]byte(prev));   h.Write([]byte{0})
    h.Write([]byte(rec.ID)); h.Write([]byte{0})
    h.Write([]byte(strconv.FormatInt(rec.TS, 10))); h.Write([]byte{0})
    h.Write([]byte(rec.Type)); h.Write([]byte{0})
    h.Write([]byte(rec.Payload))
    return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
```

每条记录存 `prev_hash` 和 `hash`，追加时在同一个事务里读取当前链头。

### 校验点

- `GET /readyz` **每次都重新遍历整条链并重算每一个哈希**
  （见 `deploy/k3s/agentgate.yaml` 的探针配置）。
  也就是说：链断了，这个实例就从负载均衡里摘出去
- CLI：`agentgate-cli audit verify`
- 管理 API：`/admin/audit/verify`
- 红队 runner 在最后一步校验一次（"如果上面真的动了目标系统，记录在这里"）

### 为什么不做成 append-only 存储或外部 WORM

P0/P1 阶段的目标是**让静默修改变得可检测**，不是"让修改不可能"。
哈希链以极低的复杂度达到了前者：无外部依赖、单文件 SQLite 也能用、
校验是纯计算。外部签名 / WORM 是后续步骤，需要先确认部署形态。

## 后果

**正向**
- 改任意一条记录的 payload → 它自己的哈希对不上，`VerifyChain` 报出 `broken_at`
- 删中间一条 → 后一条的 `prev_hash` 对不上
- 校验通过时能给出链长和链头哈希，可以用来做"外部锚定"（把这一个哈希存到别处）
- 实现成本低：一个 `chainHash` 函数 + 一张表 + 一个校验循环

**明确的边界**

1. **不能阻止重写整条链。** 有数据库写权限的人可以从创世记录开始重算。
   哈希链的可信度上限是"外部锚定频率"——把链头哈希定期写到别处（Git commit、
   对象存储、另一套系统），才能把可信度延伸到网关之外。当前未实现，
   但 `/readyz` 的响应里带链头，便于外部采集。
2. **多副本共享数据库时不安全。** `AppendAudit` 用进程内互斥锁串行化追加，
   同一时刻只有一个进程能读链头、写新记录。两个网关副本指向同一个 Postgres 时，
   会出现"两个进程同时读到同一个链头"的分叉。
   正确做法是数据库级的串行化（`SELECT ... FOR UPDATE` 锁住链头，或
   用 `INSERT ... SELECT` 把链头读取放进同一语句）。**当前未实现**，
   这是 `deploy/k3s/agentgate.yaml` 里副本数保持 1 的原因，
   也是这套东西还不能上生产的原因之一。
3. **不做加密。** 记录是明文 JSON（含已归一化的动作）。密钥材料在写入前
   已被 `adapters.Sanitize` 过滤，但 payload 里仍可能含敏感**业务**数据。
   需要静态加密的话是存储层的事。

## 一个实现细节：写什么，不写什么

请求入口只记录参数的**摘要**，不记录原始参数：

```go
g.audit.MustRecord(ctx, requestID, store.EvRequestReceived, map[string]any{
    "tool":        tool,
    "args_digest": digestArgs(args),   // sha256 前 8 字节
    "remote_note": "raw arguments are deliberately not logged; only a digest",
})
```

原因：注入到 Agent 工具调用里的内容，正是我们**最不想抄进审计数据库**的东西。
审计需要的是"这次调用对应哪个动作"，而不是原始载荷本身——
原始载荷已经在 `Action.Raw` 里（也只在那一次归一化的记录里）。

## 事件类型

审计事件用常量定义，保证 replay UI、CLI 和红队 harness 对同一组名字达成一致：

```
request.received → auth.verified → action.normalized → policy.decision
  → approval.requested → approval.granted|rejected|expired
  → preview.result → execute.started → execute.result|failed
  → rollback.result → response.returned
```

这条序列就是 `docs/threat-model.md` 里"一次调用的完整路径"的机器可读版本。

## 相关

- ADR-0001、ADR-0004
- `internal/store/sql.go`、`internal/audit/audit.go`、`internal/gateway/admin.go`
- 测试：`TestAuditChainDetectsTampering`、`TestAuditChainDetectsDeletion`、
  `TestConcurrentAppendsKeepTheChainIntact`
