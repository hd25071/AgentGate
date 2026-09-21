# ADR-0002：Kubernetes 适配器用 REST，不用 client-go

- 状态：已采纳
- 日期：2026-09

## 背景

网关需要对 Kubernetes 做四件事：读对象、apply（带 server-side dry-run）、
delete、scale（以及 exec，见下）。Go 生态的默认答案是 `k8s.io/client-go`。

同时，MCP 协议层也面临一个类似选择：用官方 Go SDK，还是自己实现。

## 决策

**两者都自己实现**，不引入 `client-go`，不引入官方 MCP Go SDK。

- K8s 适配器直接用 `net/http` 打 API Server 的 REST 接口
  （`internal/adapters/k8s.go`），dry-run 用 `?dryRun=All` + server-side apply。
- MCP 层自己实现 JSON-RPC 2.0（`internal/mcp/`），只覆盖
  `initialize` / `tools/list` / `tools/call` / `ping` 和两个通知。

## 理由

**1. 信任边界越小越好。**
`client-go` 会把 `k8s.io/api`、`k8s.io/apimachinery`、`k8s.io/client-go` 整棵树
拉进二进制——包含 informer、workqueue、discovery、缓存、以及若干把
"访问集群"变容易的便捷 API。这个网关的定位是**窄的调解点**，
引入一个"什么都能做"的客户端库，等于把一整棵攻击面放进 TCB。

**2. 需要的是 5 个 REST 调用，不是一个框架。**
真正用到的路径：

```
GET    /api/v1/namespaces/{ns}/{resource}/{name}
POST   /apply   (PATCH + fieldManager + force)
PATCH  {resource}/{name}          # scale 走 /scale 子资源
DELETE {resource}/{name}
```

这一段不到两百行，而且每一行都能被读懂、被审计。

**3. server-side dry-run 是策略的前提，不是可选项。**
`?dryRun=All` 让"改之前先问集群这改动是否合法"变成一次真实调用。
用 client-go 也能做，但用 REST 更清楚：dry-run 和真实请求走的是同一个函数，
只有查询参数不同——**"预演"和"执行"用同一条代码路径**，这一点值得刻意保持。
预演失败 = 硬停（已知这次改动是坏的，没有可执行的东西）。

**4. 官方 MCP Go SDK 当时仍在快速演进。**
网关需要的协议面很小；把它握在自己手里，就不需要为了追 SDK 的
破坏性变更而改动信任边界内的代码。

## 后果

**正向**
- 二进制小，依赖少，审计面窄
- dry-run 与真实请求共用代码路径
- 凭证解析明确：显式配置 → in-cluster service account → kubeconfig，三条路径都在一处

**代价 / 明确的缺口**
- **`exec` 在 `cluster` 模式下未实现**。真实 exec 需要 SPDY/WebSocket 协议升级，
  自己实现它会让信任边界变大，也超出当前阶段。所以适配器**明确拒绝**并说明原因，
  而不是假装成功或静默降级：
  ```
  the adapter does not implement interactive exec; use a debug Job
  ```
  Mock 模式下 exec 是实现了的（模拟器），因为策略引擎需要有东西可保护。
- 没有 informer 缓存：每次读都打 API Server。对网关的调用量来说这是可接受的成本，
  换来的是"读到的就是当前的"，这对审计更友好。
- 需要自己维护 kind → resource 的映射表（含 cluster-scoped 判断）。

## 什么时候该推翻这个决策

如果出现以下任一情况，重新评估：

- 需要 watch / list 大量对象（网关目前不做这件事）
- 需要支持大量 CRD，且其 resource 名无法通过映射表维护
- 必须实现 `exec`（届时需要 SPDY 客户端，可以只引入 `k8s.io/apimachinery` 的相关部分）

## 相关

- ADR-0001 执行网关整体设计
- `internal/adapters/k8s.go`、`internal/adapters/k8s_mock.go`
