# ADR-0004：审批绑定到动作哈希，并关掉 TOCTOU 缺口

- 状态：已采纳
- 日期：2026-09

## 背景

网关对中风险动作的处理是"挂起，等人批"。这一步有两种做法：

**做法 A（常见）**：把请求存进队列表，审批人在界面上看到
"agent-1 想删除 staging 的 web Deployment"，点同意，网关执行那条**存下来的请求**。

问题在于"那条存下来的请求"到底是什么。如果队列里存的是原始参数，
审批人看到的是渲染后的一句话，执行的是原始参数——中间隔着一个渲染过程。
攻击面就在这里：

- 审批界面的文案可以被构造得人畜无害（"清理缓存"），实际参数是 `FLUSHALL`
- 参数在审批和执行之间被改掉（TOCTOU）
- 审批人看到的是 A 对象，API Server 收到的是 B 对象

**做法 B（本实现）**：审批的对象是一个**密码学意义上的动作指纹**。

## 决策

### 1. 审批绑定到 action hash

- 动作归一化后立刻计算 `sha256:` 语义哈希（见 ADR-0003）
- 审批队列存的是 Action 的 JSON + 它的哈希
- **审批人必须引用哈希才能投票**：`Vote(... actionHash)`，
  哈希不匹配直接拒绝投票
- 执行前重新从存储里读出 Action，**重新计算哈希并比对**，
  不一致立即中止并记审计

```go
// internal/executor/executor.go
if err := req.Action.VerifyHash(req.Action.Hash); err != nil {
    // 完整性校验失败，任何副作用都不会发生
}
```

这条检查放在**副作用之前的最后一行**，是刻意的位置选择。

### 2. 自审批与重复投票被结构性拒绝

- `actor == ap.Subject` → 拒绝。发起者不能批自己的动作
- 同一 actor 第二次投票 → 拒绝
- 高风险（prod + 不可逆 / prod + 大范围删除）→ 需要两个人（`dual` 规则）

### 3. 审批人在界面上看到的是归一化结果

审批卡展示的是：归一化后的 Action、blast radius、策略命中的理由、
预演结果、**回滚能力的确切措辞**。

回滚措辞不用模糊表达，例如：

- `full object captured; rollback re-applies the captured manifest`
- `exec has no rollback: whatever the process did stands`
- `best effort`

"我们抓了完整对象"和"尽力而为"是对审批人**不同的承诺**。给不出就是 `""`，
而不是默认暗示可以干净回滚。

### 4. 审批通过后不是"执行存下来的参数"，而是"重新校验后执行"

`resumeApproved` 的输入只有 approval id：

```go
a, err := approval.LoadAction(ap)   // 解码 + 重新校验哈希
if err != nil { /* 拒绝执行，状态置 failed */ }
```

注意这里**没有**原始参数这个东西。参数早就不在管道里了，
只剩下 Action 本身，以及它必须通过的那次校验。

## 后果

**正向**
- "批准的 A、执行的 B"在结构上不可能：变了就是另一个哈希，得重新批
- K8s 特有的"参数名 vs manifest 名不一致"有独立规则拦截
  （URL 路径来自参数，对象身份来自 manifest，不一致时审批人与 API Server 看的不是同一个对象）
- 审批人对"能不能回滚"得到的是诚实答案

**代价**
- 哈希刻意过度敏感（见 ADR-0003），所以同一件事的两种写法要各批一次。
  这是拿可用性换确定性，取舍是明确记录过的
- 审批记录必须自包含（要存整个 Action JSON），存储会大一些
- 需要处理"审批通过但执行时哈希对不上"的路径：置为 `failed` 并写审计，
  而不是重试或降级执行

## 未做（P0/P1 边界）

- 审批 API 只有令牌认证，没有 SSO / 角色映射；"谁能批什么"目前在同一权限层
- 没有"审批人需具备某个 scope"的校验（例如只有 `break-glass` 才能批不可逆动作）
- 没有审批的二次确认（如要求输入动作哈希前 8 位。当前是引用完整哈希，靠界面提供）

## 相关

- ADR-0001、ADR-0003、ADR-0005
- `internal/approval/approval.go`、`internal/executor/executor.go`
- 测试：`TestVerifyHashDetectsTampering`、`TestPipelineApprovalRoundTrip`
