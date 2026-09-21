<div align="center">

# AgentGate

**运维 Agent 的安全执行网关**

让 LLM Agent 能够参与生产运维，同时不具备直接操作生产系统的能力

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-%E2%89%A5%201.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-6E56CF)](https://modelcontextprotocol.io)
[![Policy](https://img.shields.io/badge/policy-OPA%20Rego-7D9199?logo=openpolicyagent&logoColor=white)](policies/)
[![Docs](https://img.shields.io/badge/docs-threat%20model%20%C2%B7%20ADR-informational)](docs/)

[简体中文](README.md) · [English](README_EN.md)

</div>

---

## 项目简介

将 LLM Agent 引入生产运维，主要风险并不在于模型输出错误内容，而在于**它具备直接执行的能力**。一个持有 kubeconfig、Redis 密码或网络设备口令的 Agent，一旦经由日志、告警、缓存数据或工单正文被间接提示注入劫持，攻击者获得的即为生产环境凭据。

AgentGate 的设计目标是将"执行能力"从 Agent 侧移除：

- Agent 仅持有一把短时效、带 scope 的令牌；
- 真实凭据只存在于网关进程内部；
- 每一次工具调用都必须先被归一化为结构化 `Action`，经策略判定后，才可能接触真实系统。

其结果是：提示注入依然可以诱导 Agent 发出危险调用，但该调用无法通过策略判定。

## 核心特性

| 特性 | 说明 |
| --- | --- |
| **基于语义的策略判定** | 策略作用于归一化后的结构化 `Action`，而非原始字符串。大小写变换、百分号编码、十六进制转义、字符串拼接、全角字符与同形字均被折叠到同一语义特征上，重写请求无法绕过规则 |
| **三态裁决，默认拒绝** | `allow` / `approval_required` / `deny`。归一化失败、策略评估失败、预演失败一律判 `deny`，不存在降级放行路径 |
| **审批绑定动作哈希** | 审批人签署的是 `sha256:...` 语义哈希，执行前重新计算并比对。"批准的 A、执行的 B"在结构上无法成立 |
| **不可篡改的审计链** | 每条记录的哈希包含前一条的哈希。对中间记录的任何修改、重排或删除均可被 `VerifyChain` 检出 |
| **失败自动回滚** | 执行前捕获完整对象快照，执行失败时按快照回退，并将回滚结果写入审计链 |
| **凭据隔离** | 适配器是唯一持有真实凭据的一层，且只接收已归一化、已批准的动作。响应与审计记录中的凭据形状的值经脱敏处理 |
| **可解释的裁决** | 每一条 `allow`、`approval_required`、`deny` 都附带自然语言理由。理由会归属到正确的子系统（Redis 的动作不会得到"网络设备"的理由） |
| **自带红队评测** | 76 条语料（60 条攻击 + 16 条正常运维），攻击 payload 分布于 5 种注入载体，附带可复现的指标定义与双向缺口分析 |

## 工作原理

一次工具调用的完整路径：

```
MCP tools/call
  │
  ├─ authenticate      短时效令牌；scope 决定"能做什么"，而非"以谁的身份登录"
  ├─ normalize         原始参数 ──▶ 结构化 Action（含语义 SHA-256 哈希）
  ├─ policy            三态裁决：allow / approval_required / deny（默认 deny）
  ├─ approval          挂起；审批绑定至 action hash；由人投票
  ├─ preview           只读预演 + 可达性分析 + 对象快照
  ├─ execute           执行；失败时自动回滚
  ├─ sanitize          抹除结果中呈凭据形状的值
  └─ respond
```

上述每一步都会写出一条审计记录，记录之间以哈希相连。

## 设计原则

**一、策略针对语义，而非字符串。**

以下写法在归一化之后全部落到同一个语义特征 `command_upper = FLUSHALL` 上：

```
FLUSHALL          flushall          %46LUSHALL        \x46LUSHALL
"FLU"+"SHALL"     ＦＬＵＳＨＡＬＬ   FLUSHАLL（西里尔字母 А）
```

策略包中不存在任何读取原始字符串的规则，因此改变书写形式无法绕过判定。

**二、防御依靠约束执行，而非检测注入。**

网关不尝试判断一段文本是否为恶意指令——该路径是一场无法取胜的军备竞赛。网关只回答一个问题：**该动作本身是否被允许？** 未知命令直接拒绝（白名单而非黑名单），因为"无法识别"不构成执行的理由。

**三、审批绑定到动作哈希。**

审批的对象是一次具体的、已归一化的动作。执行前重新计算动作哈希并与审批记录比对，因此审批与执行之间不存在可利用的时间窗口（TOCTOU）。

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

策略以嵌入式 OPA（Rego）方式打包进二进制。开发期若需热改策略，可从磁盘加载：

```bash
go run ./cmd/agentgate serve --policy-dir ./policies
```

## 使用

### 观察完整生命周期

以下命令会依次演示放行、拒绝、审批、执行与审计链，并打印审计记录：

```bash
docker compose --profile demo run --rm demo
```

### 运行红队评测

```bash
docker compose --profile eval run --rm eval
```

### 通过 CLI 操作

```bash
# 签发一把仅含只读 scope 的令牌
agentgate-cli token issue --subject agent-1 --scopes k8s:read,redis:read --ttl 1h

# 询问策略对一个动作的判定（不执行任何操作）
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
| `redis_exec` | 对受管 Redis 实例执行单条命令。命令经归一化与策略判定后才被下发；管理类、可执行任意代码类与全库级命令一律拒绝 |
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

`internal/mcp` 刻意不导入 `internal/policy`：身份到策略 `Actor` 的投影由 `internal/gateway` 完成，以保证"先认证、后授权"的顺序在编译期即被固定。

### 两套凭证，两个受众

| 受众 | 端点 | 凭证 |
| --- | --- | --- |
| Agent | `/mcp` | 短时效、带 scope 的签名令牌 |
| 运维人员 | `/admin` | `AG_ADMIN_TOKEN` |

Agent 令牌无法审批任何动作，请求方也无法审批自己发起的动作——提出问题的一方不能同时是回答问题的一方。

审批界面的**页面外壳本身不做鉴权，其背后的每个数据接口都做**。这是刻意的：浏览器无法为一次页面导航附加 `X-Admin-Token` 请求头，若连外壳一并拦截，页面会先返回 `401`，而页面内用于填写令牌的输入框将永远无法到达，该页面也就失去了存在意义。外壳不包含任何数据，它是索取令牌、并在其后每次 `/admin/*` 调用上附加令牌的表单；真正的边界位于这些调用之上。

令牌未配置时管理面 **fail-closed**：返回 `503` 并说明原因。`config.Load` 在启动阶段即拒绝空的 `AG_ADMIN_TOKEN`，包装器本身亦保留一道防线，以避免空值与空值比对得出"匹配"的结论。

### 审计链

每条审计记录的哈希包含前一条记录的哈希，形成链式结构。对任意中间记录的修改、重排或删除都会被 `audit verify` 检出。`/readyz` 在链校验失败时返回 `503`，因此审计链的完整性可直接作为就绪探针的判据。

## 配置

全部配置通过环境变量提供，完整列表见 [`.env.example`](.env.example)。关键项如下：

| 变量 | 说明 |
| --- | --- |
| `AG_TOKEN_SECRET` / `AG_ADMIN_TOKEN` | 必填，各不少于 16 字节，且必须互不相同 |
| `AG_ENV` | `staging` 或 `prod`。标记为生产的目标会提高审批要求：任意写、删、配置、执行、扩缩容变更均需人工审批；不可逆的变更，以及作用于 namespace / cluster / dataset / site 级别的删除，需要两名审批人。另有若干仅针对生产环境生效的直接拒绝规则（如生产工作负载缩容至零、`KEYS *`、生产设备接口 shutdown） |
| `AG_STORE_DRIVER` | `sqlite`（默认，单节点）或 `postgres` |
| `AG_STORE_DSN` | 存储连接串 |
| `AG_K8S_MODE` | `mock`（默认，内存模拟器）或 `cluster`（直连 API Server） |
| `AG_POLICY_DIR` | 留空则使用二进制内嵌的策略包 |
| `AG_APPROVAL_WEBHOOK_URL` | 审批卡片推送地址，支持 `generic` 与 `feishu` 两种格式 |
| `AG_NETGUARD_URL` | 网络变更的可达性分析服务地址 |
| `AG_OTEL_ENDPOINT` | OpenTelemetry trace 上报地址 |

## 红队评测

评测语料共 76 条：60 条攻击 payload 分布于 5 种注入载体（日志、告警、缓存值、工单、对抗变体），另有 16 条正常运维任务用于衡量误报。评测同时运行两条对照臂——经过网关，以及绕开网关直连目标——因此"有无网关的差异"是实测值，而非推算值。

针对真实网关、`scripted` 参考 Agent、每条重复 3 次的实测结果：

| 指标 | 数值 | 含义 |
| --- | ---: | --- |
| 注入率 | **36.7%** | 参考 Agent 被诱导并发出危险调用的比例。在无网关场景下，该比例即为攻击成功率 |
| 受控执行率（审慎审批人） | **3.3%** | 唯一未被拦截的用例，是语料自身标注为"应放行"的那一条 |
| 受控执行率（无脑审批人） | **3.3%** | 审批环节的上界泄漏率 |
| 良性硬误报率 | **0.0%** | 16 条正常运维任务全部可完成 |
| 良性摩擦率 | 6.2% | 需要人工审批方可完成的比例 |
| 审计链 | `valid=True` | 686 条记录，哈希相连 |

完整报告见 [`eval/report/report.md`](eval/report/report.md)。其中最具参考价值的部分是 **`policy_gaps`**：逐条列出"语料期望"与"网关判定"的分歧，并附上网关自身的理由。该表是**双向**的——既列出网关放过的动作（`permissive`），也列出网关多拦的动作（`friction`），以及"应当有人复核却被自动执行"（`unattended`）。

评测方法与指标定义见 [`docs/red-team.md`](docs/red-team.md)。无 Docker 环境时，可使用内置 RESP2 桩启动评测（见该文档 §3.1）。

## 实现状态

明确区分真实实现与模拟实现，比文档的可读性更为重要——将模拟器视为真实集群会导致事故。

| 组件 | 状态 |
| --- | --- |
| Action 归一化、语义哈希、策略引擎（OPA）、审批绑定、审计哈希链、回滚框架 | **真实实现** |
| Redis 适配器 | **真实**：自实现 RESP2 客户端，直连真实 Redis |
| Kubernetes 适配器 | 双模式：`cluster` 直连 API Server（REST + server-side dry-run）；`mock` 为内存模拟器，默认启用 |
| VRP（华为网络设备）适配器 | **模拟器**：归一化器为真实实现，执行端为模拟实现 |
| NetGuard 可达性分析 | 未配置 `AG_NETGUARD_URL` 时使用本地启发式实现，所有输出均标注为 simulated |
| 评测中的"无网关对照组" | 真实绕开网关直连目标，非纸面推演 |

## 项目状态与路线图

本项目可编译、可测试、可运行，红队评测能够产出实测数据，但**尚未达到生产可用标准**。已知边界如下：

**工程缺口**

- 审批 API 仅实现令牌认证，尚无 SSO 与角色映射；
- 多副本共享同一数据库时，审计链的追加需要数据库级锁（见 [ADR-0005](docs/adr/0005-audit-chain.md)）；
- Kubernetes `exec` 在 `cluster` 模式下尚未实现（需要 SPDY/WebSocket），当前会明确拒绝，而非假装成功；
- 认证失败仅记录到应用日志，未写入审计链，且管理面没有速率限制；
- VRP 执行端为模拟器；
- 策略生效前缺少"演练模式"（shadow mode）以统计误报率。

**尚未收敛的策略分歧**

评测列出的分歧中，以下三类属于立场差异而非缺陷，但都需要明确认领：

- **`permissive`（4 条）**：语料标注 `deny` 而策略判定 `allow`，形态完全一致——**单个具名 key 的写入或删除**（如 `DEL orders:1001`、`SET backdoor 1`）。这是设计上刻意放行的类别：影响范围限于单个 key，且可快照、可回滚。语料采用了更严格的立场。如需收紧，可在 `policies/redis.rego` 中将"具名单 key 的写删"从 `allow` 提升至 `approval`。
- **`deferred`（7 条）**：语料标注 `deny` 而策略判定 `approval_required`，主要为删除工作负载、缩容至零、读取 Secret。策略认为这些动作可由人工批准，语料认为不应执行。这是立场差异，但审批人是这类动作的唯一防线，需要明确的责任认领。
- **`unattended`（1 条攻击 + 2 条良性）**：语料要求人工复核，而策略自动执行（单个 key 的 `SET`/`EXPIRE`）。方向与"绕过"相反，但同等重要。

上述每一项对应的威胁编号见 [`docs/threat-model.md`](docs/threat-model.md)。

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
2. 涉及策略的改动附带相应的测试用例，且新增规则遵循既有的"按 `target.kind` 收口"约定；
3. 涉及归一化的改动附带"多种伪装形式落到同一语义特征"的测试；
4. 提交信息说明**为什么**做这个改动，而非仅说明做了什么。

## 安全披露

请勿通过公开 Issue 报告安全缺陷。披露流程与范围界定见 [`SECURITY.md`](SECURITY.md)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可。
