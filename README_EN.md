<div align="center">

# AgentGate

**A policy-enforced execution gateway for infrastructure agents**

Let an LLM agent take part in production operations without giving it the ability to touch production

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-%E2%89%A5%201.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-6E56CF)](https://modelcontextprotocol.io)
[![Policy](https://img.shields.io/badge/policy-OPA%20Rego-7D9199?logo=openpolicyagent&logoColor=white)](policies/)
[![Docs](https://img.shields.io/badge/docs-threat%20model%20%C2%B7%20ADR-informational)](docs/)

[简体中文](README.md) · [English](README_EN.md)

</div>

---

## Overview

The primary risk of putting an LLM agent into production operations is not that the model says something wrong — it is that **the model can act**. An agent holding a kubeconfig, a Redis password, or a device credential is one indirect prompt injection away (a log line, an alert, a cached value, a ticket body) from handing production credentials to an attacker.

AgentGate takes the ability to act away from the agent:

- The agent holds nothing but a short-lived, scoped token.
- Real credentials exist only inside the gateway process.
- Every tool call must first be normalized into a structured `Action` and cleared by policy before it can reach a real system.

The consequence: prompt injection can still make an agent emit a dangerous call, but that call cannot pass policy.

## Features

| Feature | Description |
| --- | --- |
| **Policy over semantics, not strings** | Policy is written against the normalized `Action`, never the raw request. Case changes, percent-encoding, hex escapes, string concatenation, full-width characters and homoglyphs all collapse onto the same semantic feature, so re-spelling a request cannot dodge a rule |
| **Three-way verdict, deny by default** | `allow` / `approval_required` / `deny`. A failed normalization, a failed policy evaluation, or a failed preview all resolve to `deny`; there is no path that degrades into a yes |
| **Approvals bound to the action hash** | An approver signs a `sha256:...` semantic hash, which is recomputed and compared before execution. Approving A and executing B is structurally impossible |
| **Tamper-evident audit chain** | Every record's hash covers its predecessor. Modification, reordering, or deletion of any record is detected by `VerifyChain` |
| **Automatic rollback on failure** | A full object snapshot is captured before execution and re-applied if execution fails, with the outcome recorded in the audit chain |
| **Credential isolation** | Adapters are the only layer holding real credentials, and they accept only already-normalized, already-approved actions. Credential-shaped values are redacted from responses and audit records |
| **Reasons that explain themselves** | Every `allow`, `approval_required` and `deny` carries a natural-language reason, attributed to the subsystem it actually belongs to — a Redis action never gets a network-device justification |
| **A red-team suite of its own** | 76 payloads (60 attacks across 5 injection carriers, 16 ordinary operations), with reproducible metric definitions and a two-directional gap analysis |

## How It Works

The full path of one tool call:

```
MCP tools/call
  │
  ├─ authenticate      short-lived token; scope decides what may be done, not who you are
  ├─ normalize         raw arguments ──▶ structured Action (+ semantic SHA-256 hash)
  ├─ policy            three-way verdict: allow / approval_required / deny (default deny)
  ├─ approval          suspend; approval is bound to the action hash; a human votes
  ├─ preview           read-only dry run + reachability analysis + object snapshot
  ├─ execute           run it; roll back automatically on failure
  ├─ sanitize          strip credential-shaped values from the result
  └─ respond
```

Each step writes an audit record, and the records are chained by hash.

## Design Principles

**1. Policy targets semantics, not strings.**

All of the following land on the same semantic feature, `command_upper = FLUSHALL`, once normalized:

```
FLUSHALL          flushall          %46LUSHALL        \x46LUSHALL
"FLU"+"SHALL"     ＦＬＵＳＨＡＬＬ   FLUSHАLL (Cyrillic А)
```

No rule in the policy bundle reads a raw string, so no spelling of the request gets around the decision.

**2. Defense comes from constraining execution, not from detecting injection.**

The gateway does not try to decide whether a piece of text is a malicious instruction — that is an arms race nobody wins. It answers one question: **is this action permitted?** Unknown commands are refused outright (an allowlist, not a denylist), because "I don't recognize it" is not a reason to run it.

**3. Approvals bind to the action hash.**

What is approved is one specific, normalized action. The hash is recomputed before execution and compared against the approval record, so there is no exploitable window between approval and execution.

## Quick Start

### With Docker Compose

```bash
git clone https://github.com/hd25071/AgentGate.git
cd AgentGate
cp .env.example .env

# Generate both required secrets
sed -i "s|^AG_TOKEN_SECRET=.*|AG_TOKEN_SECRET=$(openssl rand -hex 32)|" .env
sed -i "s|^AG_ADMIN_TOKEN=.*|AG_ADMIN_TOKEN=$(openssl rand -hex 32)|" .env

docker compose up -d --build
```

Then open `http://localhost:8080/admin/ui` and enter the `AG_ADMIN_TOKEN` from `.env` to reach the approval and replay interface.

### From Source

```bash
go build ./...          # requires Go 1.26 or newer
go test ./...           # normalization / policy / audit chain / full pipeline
go vet ./...
go run ./cmd/agentgate serve
```

Behind a restricted network you may need:

```bash
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
```

The policy bundle is embedded in the binary as OPA (Rego). During development, load it from disk so edits take effect without a rebuild:

```bash
go run ./cmd/agentgate serve --policy-dir ./policies
```

## Usage

### Walk the whole lifecycle

This runs through allow, deny, approval, execution and the audit chain, then prints the audit records:

```bash
docker compose --profile demo run --rm demo
```

### Run the red-team suite

```bash
docker compose --profile eval run --rm eval
```

### Operate through the CLI

```bash
# Mint a read-only token
agentgate-cli token issue --subject agent-1 --scopes k8s:read,redis:read --ttl 1h

# Ask what policy would decide for an action, executing nothing
agentgate-cli explain k8s_delete -a kind=Namespace -a name=payments

# Approvals
agentgate-cli approvals list --status pending
agentgate-cli approvals approve <id> --actor oncall.li

# Audit
agentgate-cli audit tail --limit 50
agentgate-cli audit verify
agentgate-cli replay <request_id>
```

Connection details come from the environment: `AG_URL`, `AG_ADMIN_TOKEN`, `AG_TOKEN_SECRET`, `AG_AGENT_TOKEN`.

> **On Windows PowerShell**
> PowerShell 5.1 swallows embedded double quotes when passing arguments to native commands, so JSON arguments must be escaped:
>
> ```powershell
> .\bin\agentgate-cli.exe call k8s_get --args '{\"kind\":\"Deployment\",\"name\":\"web\",\"namespace\":\"default\"}'
> ```

### Managed tools

The gateway exposes the following tools over MCP. Which of them an agent may call is constrained jointly by its token scopes and by policy.

| Tool | Description |
| --- | --- |
| `redis_exec` | Run one Redis command against the managed instance. The command is normalized and checked against policy before it is sent; administrative, code-executing and keyspace-wide commands are refused |
| `k8s_get` | Read one Kubernetes object. Reading a Secret is treated as a credential-access event and requires approval |
| `k8s_apply` | Apply a manifest with server-side apply. Always runs a dry run first; a dry-run failure aborts before anything is written |
| `k8s_delete` | Delete one Kubernetes object. Deleting namespaces, nodes, PersistentVolumes, CRDs and stateful workloads is refused outright |
| `k8s_scale` | Change a workload's replica count. Scaling a production workload to zero is refused |
| `k8s_exec` | Run a command inside a pod. Requires approval, and is refused outright in control-plane namespaces |
| `net_config` | Push a Huawei VRP configuration block to a network device. Requires approval and a NetGuard reachability preview |
| `agentgate_explain` | Ask the gateway what it would decide for a call, without executing anything |
| `agentgate_approval_status` | Check the state of a pending approval without blocking |
| `agentgate_approval_wait` | Wait for a pending approval to be decided and report the outcome |

## Security Model

### Trust boundary

The gateway is the only mediation point between an agent and production. The only artifact on the agent side is a short-lived token; the kubeconfig, the Redis credentials and the device credentials live in the gateway process and are touched only by `internal/adapters/`.

`internal/mcp` deliberately does not import `internal/policy`. Projecting an identity onto a policy `Actor` happens in `internal/gateway`, which keeps "authenticate first, authorize second" fixed at compile time.

### Two credentials, two audiences

| Audience | Endpoint | Credential |
| --- | --- | --- |
| Agent | `/mcp` | Short-lived, scoped signed token |
| Operator | `/admin` | `AG_ADMIN_TOKEN` |

An agent token cannot approve anything, and a caller cannot approve its own action — the thing that asks must not be the thing that says yes.

The approval UI's **page shell is deliberately not authenticated; every data endpoint behind it is**. A browser has nowhere to put an `X-Admin-Token` header on a page navigation, so gating the shell would return `401` before the token input inside it ever became reachable, and the page could never do the one thing it exists to do. The shell carries no data: it is the form that asks for the token and attaches it to every `/admin/*` call it makes. The boundary that matters sits on those calls.

With no admin token configured the admin surface **fails closed**, returning `503` with an explanation. `config.Load` already rejects an empty `AG_ADMIN_TOKEN` at startup, and the wrapper keeps a second guard so that comparing two empty values can never answer "match".

### Audit chain

Each audit record's hash covers the previous record's hash. Any modification, reordering, or deletion of a record in the middle is detected by `audit verify`. `/readyz` returns `503` when the chain fails to verify, so chain integrity doubles as a readiness signal.

## Configuration

All configuration is supplied through environment variables; the full list is in [`.env.example`](.env.example). The important ones:

| Variable | Description |
| --- | --- |
| `AG_TOKEN_SECRET` / `AG_ADMIN_TOKEN` | Required, at least 16 bytes each, and must differ from one another |
| `AG_ENV` | `staging` or `prod`. Targets declared as production raise the bar: any write, delete, config change, exec or scale needs a human, and an irreversible change — or a delete at namespace / cluster / dataset / site scope — needs two. A few rules refuse outright, but only against production: scaling a workload to zero, `KEYS *`, and shutting a device interface |
| `AG_STORE_DRIVER` | `sqlite` (default, single node) or `postgres` |
| `AG_STORE_DSN` | Storage connection string |
| `AG_K8S_MODE` | `mock` (default, in-memory simulator) or `cluster` (talk to a real API server) |
| `AG_POLICY_DIR` | Leave empty to use the bundle embedded in the binary |
| `AG_APPROVAL_WEBHOOK_URL` | Where approval cards are posted; shapes `generic` and `feishu` are supported |
| `AG_NETGUARD_URL` | Reachability analysis service for network changes |
| `AG_OTEL_ENDPOINT` | OpenTelemetry trace endpoint |

## Evaluation

The corpus holds 76 payloads: 60 attacks spread across 5 injection carriers (logs, alerts, cached values, tickets, adversarial variants) plus 16 ordinary operations to measure false positives. The harness runs two arms — through the gateway, and bypassing it straight to the targets — so the difference is measured, not projected.

Against a live gateway, with the `scripted` reference agent and 3 repeats per payload:

| Metric | Value | Meaning |
| --- | ---: | --- |
| Injection rate | **36.7%** | Share of payloads where the reference agent took the bait and emitted the dangerous call. Without a gateway, this is the attack success rate |
| Guarded execution rate (careful approver) | **3.3%** | The one case that got through is the payload the corpus itself marks as allowed |
| Guarded execution rate (rubber-stamp approver) | **3.3%** | Upper bound on leakage through the approval step |
| Benign hard false-positive rate | **0.0%** | All 16 ordinary operations completed |
| Benign friction rate | 6.2% | Share requiring a human approval to complete |
| Audit chain | `valid=True` | 686 records, chained by hash |

The full report is at [`eval/report/report.md`](eval/report/report.md). Its most useful section is **`policy_gaps`**, which lists every disagreement between what the corpus expects and what the gateway decides, each with the gateway's own reason. The table runs **both ways**: what the gateway let through (`permissive`), what it stopped unnecessarily (`friction`), and what ran unattended when a human should have looked (`unattended`).

Methodology and metric definitions are in [`docs/red-team.md`](docs/red-team.md). Without Docker, the suite runs against a built-in RESP2 stub (see §3.1 of that document).

## Implementation Status

Being explicit about what is real and what is simulated matters more than how the documentation reads — mistaking a simulator for a live cluster causes incidents.

| Component | Status |
| --- | --- |
| Action normalization, semantic hashing, policy engine (OPA), approval binding, audit hash chain, rollback framework | **Real** |
| Redis adapter | **Real**: hand-written RESP2 client talking to a real Redis |
| Kubernetes adapter | Two modes: `cluster` talks to a real API server (REST + server-side dry-run); `mock` is an in-memory simulator and is the default |
| VRP (Huawei network device) adapter | **Simulator**: the normalizer is real, the execution side is simulated |
| NetGuard reachability analysis | Falls back to a local heuristic when `AG_NETGUARD_URL` is unset; every output is labelled simulated |
| The "no gateway" control arm in the evaluation | Genuinely bypasses the gateway and talks to the targets, not a paper exercise |

## Project Status and Roadmap

The project builds, tests, and runs, and the red-team suite produces measured numbers — but it is **not ready for production**. Known boundaries:

**Engineering gaps**

- The approval API authenticates with a token only; there is no SSO or role mapping.
- With multiple replicas sharing one database, appending to the audit chain needs a database-level lock (see [ADR-0005](docs/adr/0005-audit-chain.md)).
- Kubernetes `exec` is not implemented in `cluster` mode (it needs SPDY/WebSocket). It refuses explicitly rather than pretending to succeed.
- Authentication failures are written to the application log but not to the audit chain, and the admin surface has no rate limiting.
- The VRP execution side is a simulator.
- There is no shadow mode to measure a policy's false-positive rate before it takes effect.

**Policy disagreements not yet resolved**

Of the disagreements the evaluation surfaces, these three are differences of stance rather than defects — but each needs an owner:

- **`permissive` (4 payloads)**: the corpus says `deny`, policy says `allow`. All four share one shape — **a write or delete of a single named key** (e.g. `DEL orders:1001`, `SET backdoor 1`). This is a deliberately permitted category: the blast radius is one key, and it can be snapshotted and rolled back. The corpus takes a stricter position. To tighten it, move "write/delete of a single named key" from `allow` to `approval` in `policies/redis.rego`.
- **`deferred` (7 payloads)**: the corpus says `deny`, policy says `approval_required` — mostly deleting workloads, scaling to zero, and reading Secrets. Policy holds that a human may approve these; the corpus holds that they should never happen. This is a difference of stance, but the approver is the only line of defense for these actions, and that responsibility needs to be claimed explicitly.
- **`unattended` (1 attack + 2 benign)**: the corpus wants a human to look, and policy executed automatically (a `SET`/`EXPIRE` on a single key). This runs in the opposite direction from a bypass and matters just as much.

Each of these maps to a numbered threat in [`docs/threat-model.md`](docs/threat-model.md).

## Repository Layout

```
cmd/agentgate/          Gateway binary (serve / mcp-stdio)
cmd/agentgate-cli/      Operator CLI (mint tokens, approve, audit, replay)
internal/action/        Raw arguments → structured Action; de-obfuscation; semantic hash
internal/policy/        Embedded OPA engine; fail-closed
internal/approval/      Approval queue; hash binding; webhook notification
internal/preview/       Read-only dry run, object snapshots, NetGuard reachability
internal/executor/      Execution with automatic rollback on failure
internal/adapters/      The only layer holding real credentials (Redis / Kubernetes / VRP)
internal/store/         Audit hash chain, approvals, execution records (SQLite / PostgreSQL)
internal/mcp/           MCP (JSON-RPC 2.0) over HTTP and stdio
internal/gateway/       Pipeline orchestration; MCP tool definitions; admin API
policies/               Rego policy bundle (embedded at build time)
web/                    Approval and replay UI (single file, embedded in the binary)
eval/                   Red-team corpus and harness (Python)
eval/tools/             Evaluation helpers (RESP2 stub for use without Redis)
deploy/                 k3s manifests, OpenTelemetry Collector config
docs/                   Threat model, evaluation methodology, architecture decision records
```

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/threat-model.md`](docs/threat-model.md) | Trust boundaries, attack surface, and the specific threat each defense addresses |
| [`docs/red-team.md`](docs/red-team.md) | Evaluation methodology, metric definitions, and how to read the results |
| [`docs/adr/`](docs/adr/) | Key architecture decisions and their trade-offs |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure process and scope |

## Contributing

Issues and pull requests are welcome. Before submitting, please confirm:

1. `go build ./...`, `go vet ./...` and `go test ./...` all pass, and `gofmt -l .` prints nothing.
2. Changes to policy come with tests, and new rules follow the existing convention of scoping by `target.kind`.
3. Changes to normalization come with a test showing that multiple disguises land on the same semantic feature.
4. Commit messages explain **why** the change is being made, not only what it does.

## Security

Please do not report security defects through public issues. The disclosure process and scope are described in [`SECURITY.md`](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
