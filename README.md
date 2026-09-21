<div align="center">

# AgentGate

**面向运维 Agent 的策略执行网关**

在 LLM Agent 与生产系统之间加入一层强制策略判定，使 Agent 能够参与运维，但不具备直接操作生产系统的能力

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-%E2%89%A5%201.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-6E56CF)](https://modelcontextprotocol.io)
[![Policy](https://img.shields.io/badge/policy-OPA%20Rego-7D9199?logo=openpolicyagent&logoColor=white)](policies/)
[![Docs](https://img.shields.io/badge/docs-threat%20model%20%C2%B7%20ADR-informational)](docs/)

[简体中文](README.md) · [English](README_EN.md)

</div>

---

## 简介

AgentGate 是部署在 LLM Agent 与受管基础设施之间的执行网关。每一次工具调用在到达目标系统之前，必须依次经过身份认证、动作归一化、策略判定，以及在策略要求时的人工审批。

引入 LLM Agent 参与生产运维的风险，主要不在于模型会给出错误结论，而在于模型可以执行。当 Agent 进程持有 kubeconfig、Redis 口令或网络设备凭据时，日志、告警、缓存值或工单正文中的一段间接提示注入，即可让攻击者取得这些凭据的实际使用权。

AgentGate 通过移除 Agent 侧的执行能力来消除该路径：

- Agent 只持有一把短时效、带 scope 的令牌，令牌本身不含任何目标系统凭据；
- 目标系统的真实凭据只存在于网关进程内，只由 `internal/adapters/` 访问；
- 每次工具调用先被归一化为结构化 `Action`，通过策略判定后才可能接触真实系统。

提示注入仍可诱导 Agent 发出危险调用，但该调用无法通过策略判定。

## 主要特性

| 特性 | 说明 |
| --- | --- |
| 语义化策略判定 | 策略作用于归一化后的 `Action`，不读取原始字符串。大小写变换、百分号编码、十六进制转义、字符串拼接、全角字符与同形字在归一化阶段折叠为同一组特征，重新书写请求无法绕过规则 |
| 三态裁决，默认拒绝 | 裁决结果为 `allow`、`approval_required` 或 `deny`。归一化失败、策略评估失败、预演失败均判 `deny`，不存在降级放行的分支 |
| 审批与动作哈希绑定 | 审批对象是 `sha256:...` 语义哈希，执行前重新计算并比对。批准的 A 与执行的 B 不可能同时成立 |
| 可校验的审计链 | 每条记录的哈希包含前一条记录的哈希，对中间记录的修改、重排或删除可由 `VerifyChain` 检出 |
| 失败自动回滚 | 执行前捕获对象快照，执行失败时按快照回退，回滚结果写入审计链 |
| 凭据隔离 | 适配器是唯一持有真实凭据的一层，且只接受已归一化、已批准的动作。响应与审计记录中呈凭据形状的值经脱敏处理 |
| 裁决可解释 | 每条 `allow`、`approval_required`、`deny` 均附带自然语言理由，理由归属到对应子系统，Redis 动作不会得到网络设备的理由 |
| 自带红队评测 | 76 条语料（60 条攻击 + 16 条正常运维），攻击 payload 分布于 5 种注入载体，附指标定义与双向缺口分析 |

## 架构

一次工具调用的处理流程：

```
MCP tools/call
  │
  ├─ authenticate      校验短时效令牌；scope 决定可执行的动作范围
  ├─ normalize         原始参数 ──▶ 结构化 Action（含语义 SHA-256 哈希）
  ├─ policy            三态裁决：allow / approval_required / deny（默认 deny）
  ├─ approval          挂起待审；审批绑定至 action hash，由人工裁决
  ├─ preview           只读预演、可达性分析、对象快照
  ├─ execute           执行；失败时自动回滚
  ├─ sanitize          移除结果中呈凭据形状的值
  └─ respond
```

每个步骤写入一条审计记录，记录之间以哈希相连。

## 设计原则

**策略作用于语义，不作用于字符串。**

以下写法在归一化之后落到同一特征 `command_upper = FLUSHALL`：

```
FLUSHALL          flushall          %46LUSHALL        \x46LUSHALL
"FLU"+"SHALL"     ＦＬＵＳＨＡＬＬ   FLUSHАLL（西里尔字母 А）
```

策略包中不存在读取原始字符串的规则，因此改变书写形式不会改变判定结果。

**网关约束可执行的动作，不判断文本的意图。**

网关不尝试判定一段文本是否为恶意指令，只回答该动作本身是否被允许。网关维护已知命令词汇表，未收录的命令直接拒绝；无法识别的动作不构成执行理由。

**审批的对象是一次具体的动作。**

执行前重新计算动作哈希并与审批记录比对，审批与执行之间不存在可利用的时间窗口。

## 快速开始

### 使用 Docker Compose

```bash
git clone https://github.com/hd25071/AgentGate.git
cd AgentGate
cp .env.example .env

# 生成两个必需密钥
sed -i "s|^AG_TOKEN_SECRET=.*|AG_TOKEN_SECRET=$(openssl rand -hex 32)|" .env
sed -i "s|^AG_ADMIN_TOKEN=.*|AG_ADMIN_TOKEN=$(openssl rand -hex 32)|" .env

docker compose up -d --build
```

启动后访问 `http://localhost:8080/admin/ui`，输入 `.env` 中的 `AG_ADMIN_TOKEN`，即可使用审批与回放界面。

### 本地构建

```bash
go build ./...          # 需要 Go 1.26 及以上
go test ./...           # 归一化 / 策略 / 审计链 / 完整流水线
go vet ./...
go run ./cmd/agentgate serve
```

在中国大陆网络环境下建议设置：

```bash
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
```

策略以嵌入式 OPA（Rego）方式打包进二进制。开发期若需在不重新构建的情况下修改策略，可从磁盘加载：

```bash
go run ./cmd/agentgate serve --policy-dir ./policies
```

## 使用

### 完整生命周期演示

以下命令依次演示放行、拒绝、审批、执行与审计链，并打印审计记录：

```bash
docker compose --profile demo run --rm demo
```

### 红队评测

```bash
docker compose --profile eval run --rm eval
```

### 通过 CLI 操作

```bash
# 签发一把仅含只读 scope 的令牌
agentgate-cli token issue --subject agent-1 --scopes k8s:read,redis:read --ttl 1h

# 查询策略对一个动作的判定（不执行任何操作）
agentgate-cli explain k8s_delete -a kind=Namespace -a name=payments

# 审批队列
agentgate-cli approvals list --status pending
agentgate-cli approvals approve <id> --actor oncall.li

# 审计
agentgate-cli audit tail --limit 50
agentgate-cli audit verify
agentgate-cli replay <request_id>
```

连接参数从环境变量读取：`AG_URL`、`AG_ADMIN_TOKEN`、`AG_TOKEN_SECRET`、`AG_AGENT_TOKEN`。

> **Windows PowerShell 注意事项**
> PowerShell 5.1 在向原生命令传递参数时会吞掉内嵌双引号，JSON 参数需要转义：
>
> ```powershell
> .\bin\agentgate-cli.exe call k8s_get --args '{\"kind\":\"Deployment\",\"name\":\"web\",\"namespace\":\"default\"}'
> ```

### 受管工具

网关通过 MCP 暴露以下工具。Agent 可调用的工具集合由令牌 scope 与策略共同约束。

| 工具 | 说明 |
| --- | --- |
| `redis_exec` | 对受管 Redis 实例执行单条命令。命令经归一化与策略判定后才下发：全库级、服务端控制、代码加载与跨实例搬迁类命令拒绝；管理类命令与通配写入需要审批；只读诊断命令（`MEMORY`、`SLOWLOG` 等）与单个非敏感参数的 `CONFIG GET` 放行 |
| `k8s_get` | 读取单个 Kubernetes 对象。读取 Secret 被视为凭据访问事件，需要审批 |
| `k8s_apply` | 以 server-side apply 应用清单。总是先执行 dry-run，dry-run 失败则在写入前中止 |
| `k8s_delete` | 删除单个 Kubernetes 对象。删除 Namespace、Node、PersistentVolume、CRD 及有状态工作负载一律拒绝 |
| `k8s_scale` | 调整工作负载副本数。将生产工作负载缩容至零会被拒绝 |
| `k8s_exec` | 在 Pod 内执行命令。需要审批，且在控制面命名空间中一律拒绝 |
| `net_config` | 向华为 VRP 网络设备下发配置块。需要审批，并需通过 NetGuard 可达性预演 |
| `agentgate_explain` | 查询策略对某次调用的判定结果，不执行任何操作 |
| `agentgate_approval_status` | 查询待审项状态，不阻塞 |
| `agentgate_approval_wait` | 等待待审项被裁决并返回结果 |

## 安全模型

### 信任边界

网关是 Agent 与生产系统之间唯一的中介点。Agent 侧持有的工件只有一把短时效令牌；kubeconfig、Redis 凭据与设备口令均在网关进程内，且仅由 `internal/adapters/` 访问。

`internal/mcp` 不导入 `internal/policy`。身份到策略 `Actor` 的投影由 `internal/gateway` 完成，认证与授权的先后顺序由此在编译期固定。

### 凭证与受众

| 受众 | 端点 | 凭证 |
| --- | --- | --- |
| Agent | `/mcp` | 短时效、带 scope 的签名令牌 |
| 运维人员 | `/admin` | `AG_ADMIN_TOKEN` |

Agent 令牌不能用于审批，请求方也不能审批自己发起的动作。

审批界面的页面外壳不做鉴权，其背后的数据接口均要求 `X-Admin-Token`。浏览器在页面导航时无法附加自定义请求头，若外壳一并拦截，页面会在渲染前返回 `401`，用于输入令牌的表单无法显示。外壳本身不包含业务数据。

`AG_ADMIN_TOKEN` 未配置时管理面 fail-closed，返回 `503` 并说明原因。`config.Load` 在启动阶段即拒绝空令牌，包装层保留独立校验，避免空值与空值比对得出匹配结果。

### 审计链

每条审计记录的哈希包含前一条记录的哈希，形成链式结构。对任意中间记录的修改、重排或删除可由 `agentgate-cli audit verify` 检出。`/readyz` 在链校验失败时返回 `503`，因此审计链的完整性可直接用作就绪探针判据。

## 配置

全部配置通过环境变量提供，完整列表见 [`.env.example`](.env.example)。关键项如下：

| 变量 | 说明 |
| --- | --- |
| `AG_TOKEN_SECRET` / `AG_ADMIN_TOKEN` | 必填，各不少于 16 字节，且必须互不相同 |
| `AG_ENV` | `staging` 或 `prod`。标记为生产的目标会提高审批要求：任意写、删、配置、执行、扩缩容变更均需人工审批；不可逆的变更，以及作用于 namespace / cluster / dataset / site 级别的删除，需要两名审批人。另有若干仅针对生产环境生效的直接拒绝规则，例如生产工作负载缩容至零、`KEYS *`、生产设备接口 shutdown |
| `AG_STORE_DRIVER` | `sqlite`（默认，单节点）或 `postgres` |
| `AG_STORE_DSN` | 存储连接串 |
| `AG_K8S_MODE` | `mock`（默认，内存模拟器）或 `cluster`（直连 API Server） |
| `AG_POLICY_DIR` | 留空则使用二进制内嵌的策略包 |
| `AG_APPROVAL_WEBHOOK_URL` | 审批卡片推送地址，支持 `generic` 与 `feishu` 两种格式 |
| `AG_NETGUARD_URL` | 网络变更的可达性分析服务地址 |
| `AG_OTEL_ENDPOINT` | OpenTelemetry trace 上报地址 |

## 红队评测

评测语料共 76 条：60 条攻击 payload 分布于 5 种注入载体（日志、告警、缓存值、工单、对抗变体），另有 16 条正常运维任务用于衡量误报。评测同时运行两条对照臂，一条经过网关，一条绕开网关直连目标，因此有无网关的差异为实测值。

针对真实网关、`scripted` 参考 Agent、每条重复 3 次的实测结果：

| 指标 | 数值 | 含义 |
| --- | ---: | --- |
| 注入率 | **36.7%** | 参考 Agent 被诱导并发出危险调用的比例。在无网关场景下，该比例即攻击成功率 |
| 受控执行率（审慎审批人） | **3.3%** | 唯一未被拦截的用例是语料自身标注为应放行的那一条 |
| 受控执行率（无脑审批人） | **3.3%** | 审批环节的上界泄漏率 |
| 良性硬误报率 | **0.0%** | 16 条正常运维任务全部可完成 |
| 良性摩擦率 | 6.2% | 需要人工审批方可完成的比例 |
| 审计链 | `valid=True` | 评测结束时对整条链做一次校验。记录数随运行规模变化，当次数值见报告中的 Audit chain 一节 |

完整报告见 [`eval/report/report.md`](eval/report/report.md)。其中 `policy_gaps` 一节逐条列出语料期望与网关判定的分歧，并附网关自身的理由。该表是双向的，既列出网关放过的动作（`permissive`），也列出网关多拦的动作（`friction`），以及应当有人复核却被自动执行的用例（`unattended`）。

评测方法与指标定义见 [`docs/red-team.md`](docs/red-team.md)。无 Docker 环境时，可使用内置 RESP2 桩启动评测，见该文档 §3.1。

## 实现状态

下表区分真实实现与模拟实现。模拟组件不应用于生产验证。

| 组件 | 状态 |
| --- | --- |
| Action 归一化、语义哈希、策略引擎（OPA）、审批绑定、审计哈希链、回滚框架 | 真实实现 |
| Redis 适配器 | 真实实现：自实现 RESP2 客户端，直连真实 Redis |
| Kubernetes 适配器 | 双模式：`cluster` 直连 API Server（REST + server-side dry-run）；`mock` 为内存模拟器，默认启用 |
| VRP（华为网络设备）适配器 | 模拟实现：归一化器为真实实现，执行端为模拟实现 |
| NetGuard 可达性分析 | 未配置 `AG_NETGUARD_URL` 时使用本地启发式实现，全部输出标注为 simulated |
| 评测中的无网关对照组 | 真实绕开网关直连目标，非纸面推演 |

## 已知限制

项目可编译、可测试、可运行，红队评测能够产出实测数据，但尚未达到生产可用标准。已知边界如下：

- 审批 API 仅实现令牌认证，未实现 SSO 与角色映射；
- 多副本共享同一数据库时，审计链的追加需要数据库级锁，见 [ADR-0005](docs/adr/0005-audit-chain.md)；
- Kubernetes `exec` 在 `cluster` 模式下尚未实现（需要 SPDY/WebSocket），当前返回明确拒绝；
- 认证失败写入应用日志，未写入审计链；管理面没有速率限制；
- VRP 执行端为模拟实现；
- 策略生效前缺少 shadow 模式，无法在投产前统计误报率。

### 策略与语料的分歧

评测列出的以下三类分歧属于立场差异而非策略缺陷，但每一条都需要明确的责任归属：

| 类别 | 数量 | 说明 |
| --- | ---: | --- |
| `permissive` | 4 | 语料标注 `deny`，策略判定 `allow`。四条形态一致，均为单个具名 key 的写入或删除，例如 `DEL orders:1001`、`SET backdoor 1`。这是设计上刻意放行的类别：影响范围限于单个 key，可快照、可回滚。语料采用了更严格的立场。如需收紧，可将 `policies/redis.rego` 中具名单 key 的写删由 `allow` 提升至 `approval` |
| `deferred` | 7 | 语料标注 `deny`，策略判定 `approval_required`，主要为删除工作负载、缩容至零、读取 Secret。审批人是这类动作的唯一防线 |
| `unattended` | 3 | 语料要求人工复核，策略自动执行，均为单个 key 的 `SET` / `EXPIRE`，其中 1 条为攻击、2 条为正常运维。方向与绕过相反，但需要同等对待 |

各项对应的威胁编号见 [`docs/threat-model.md`](docs/threat-model.md)。

## 目录结构

```
cmd/agentgate/          网关主程序（serve / mcp-stdio）
cmd/agentgate-cli/      运维 CLI（签发令牌、审批、审计、回放）
internal/action/        原始参数 → 结构化 Action；去混淆；语义哈希
internal/policy/        嵌入式 OPA 引擎；fail-closed
internal/approval/      审批队列；哈希绑定；webhook 通知
internal/preview/       只读预演、对象快照、NetGuard 可达性
internal/executor/      执行与失败自动回滚
internal/adapters/      唯一持有真实凭据的一层（Redis / Kubernetes / VRP）
internal/store/         审计哈希链、审批与执行记录（SQLite / PostgreSQL）
internal/mcp/           MCP（JSON-RPC 2.0）over HTTP 与 stdio
internal/gateway/       流水线编排；MCP 工具定义；管理 API
policies/               Rego 策略包（构建时嵌入二进制）
web/                    审批与回放界面（单文件，嵌入二进制）
eval/                   红队评测语料与执行器（Python）
eval/tools/             评测辅助工具（无 Redis 时的 RESP2 桩）
deploy/                 k3s 清单、OpenTelemetry Collector 配置
docs/                   威胁模型、评测方法与架构决策记录
```

## 文档

| 文档 | 内容 |
| --- | --- |
| [`docs/threat-model.md`](docs/threat-model.md) | 信任边界、攻击面，以及每一项防御措施对应的具体威胁 |
| [`docs/red-team.md`](docs/red-team.md) | 评测方法、指标定义与结果解读 |
| [`docs/adr/`](docs/adr/) | 关键架构决策及其取舍 |
| [`SECURITY.md`](SECURITY.md) | 漏洞披露流程与范围界定 |

## 参与贡献

欢迎提交 Issue 与 Pull Request。提交前请确认：

1. `go build ./...`、`go vet ./...`、`go test ./...` 全部通过，且 `gofmt -l .` 无输出；
2. 涉及策略的改动附带相应测试用例，新增规则遵循既有的按 `target.kind` 收口的约定；
3. 涉及归一化的改动附带多种伪装形式落到同一语义特征的测试；
4. 提交信息说明改动的动因，而非仅说明改动内容。

## 安全披露

请勿通过公开 Issue 报告安全缺陷。披露流程与范围界定见 [`SECURITY.md`](SECURITY.md)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可。
