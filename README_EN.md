<div align="center">

# AgentGate

**A policy-enforced execution gateway for infrastructure agents**

Places a mandatory policy decision between an LLM agent and production systems, so the agent can take part in operations without being able to touch production directly

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-%E2%89%A5%201.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-6E56CF)](https://modelcontextprotocol.io)
[![Policy](https://img.shields.io/badge/policy-OPA%20Rego-7D9199?logo=openpolicyagent&logoColor=white)](policies/)
[![Docs](https://img.shields.io/badge/docs-threat%20model%20%C2%B7%20ADR-informational)](docs/)

[简体中文](README.md) · [English](README_EN.md)

</div>

---

## Overview

AgentGate is an execution gateway that sits between an LLM agent and managed infrastructure. Every tool call must pass, in order, through authentication, action normalization, a policy decision, and — where policy requires it — human approval, before it can reach a target system.

The primary risk of putting an LLM agent into production operations is not that the model reaches a wrong conclusion, but that the model can act. When the agent process holds a kubeconfig, a Redis password, or a device credential, a single piece of indirect prompt injection in a log line, an alert, a cached value, or a ticket body gives an attacker working use of those credentials.

AgentGate removes that path by removing execution capability from the agent side:

- The agent holds one short-lived, scoped token, which itself carries no target-system credentials;
- real credentials for target systems exist only inside the gateway process, and are read only by `internal/adapters/`;
- every tool call is first normalized into a structured `Action` and cleared by policy before it can reach a real system.

Prompt injection can still induce the agent to emit a dangerous call. The gateway does not change that; it changes the consequence. Dangerous calls are denied or routed to human approval, while single-key rollbackable writes are allowed by design. That last class, and the trade-off it makes, is itemised under [Policy disagreements](#policy-disagreements).

## Features

| Feature | Description |
| --- | --- |
| Policy over semantics | Policy is written against the normalized `Action` and never reads the raw string. Case changes, percent-encoding, hex escapes, string concatenation, full-width characters and homoglyphs are folded onto the same set of features during normalization, so re-spelling a request does not change the decision |
| Protected namespaces | Writes and deletes into `lock:`, `session:`, `feature:`, `token:` and similar prefixes require approval. Snapshot-able and rollback-able only says the bytes come back; it says nothing about whether restoring them is the right outcome |
| Session taint | Once a session has read content out of a target system — the carrier for a log line, a cached value, a ticket body — every later mutation from it requires approval. No content inspection: the gateway tracks the data flow it can see rather than guessing whether a string looks like an instruction |
| Three-way verdict, deny by default | The verdict is `allow`, `approval_required`, or `deny`. A failed normalization, a failed policy evaluation, or a failed preview all resolve to `deny`; there is no branch that degrades into a yes |
| Approvals bound to the action hash | What is approved is a `sha256:...` semantic hash, recomputed and compared before execution. Approving A and executing B cannot both hold |
| Verifiable audit chain | Each record's hash covers its predecessor. Modification, reordering, or deletion of any record is detected by `VerifyChain` |
| Automatic rollback on failure | An object snapshot is captured before execution and re-applied if execution fails; the outcome is written to the audit chain |
| Credential isolation | Adapters are the only layer holding real credentials, and they accept only normalized, approved actions. Credential-shaped values are redacted from responses and audit records |
| Explainable verdicts | Every `allow`, `approval_required` and `deny` carries a natural-language reason, attributed to the subsystem it belongs to; a Redis action never receives a network-device reason |
| A red-team suite of its own | 76 payloads (60 attacks across 5 injection carriers, 16 ordinary operations), with metric definitions and a two-directional gap analysis |

## Architecture

The path of one tool call:

```
MCP tools/call
  │
  ├─ authenticate      verify the short-lived token; scope decides which actions may be taken
  ├─ normalize         raw arguments ──▶ structured Action (+ semantic SHA-256 hash)
  ├─ policy            three-way verdict: allow / approval_required / deny (default deny)
  ├─ approval          suspend; approval is bound to the action hash and decided by a human
  ├─ preview           read-only dry run, reachability analysis, object snapshot
  ├─ execute           run it; roll back automatically on failure
  ├─ sanitize          strip credential-shaped values from the result
  └─ respond
```

Each step writes an audit record, and the records are chained by hash.

## Design Principles

**Policy targets semantics, not strings.**

All of the following land on the same feature, `command_upper = FLUSHALL`, once normalized:

```
FLUSHALL          flushall          %46LUSHALL        \x46LUSHALL
"FLU"+"SHALL"     ＦＬＵＳＨＡＬＬ   FLUSHАLL (Cyrillic А)
```

No rule in the policy bundle reads a raw string, so changing the spelling does not change the decision.

**The gateway constrains actions; it does not judge the intent of text.**

The gateway does not attempt to decide whether a piece of text is a malicious instruction. It answers only whether the action itself is permitted. It maintains a vocabulary of known commands; a command outside it is refused, and an unrecognized action is not a reason to run it.

**What is approved is one specific action.**

The action hash is recomputed before execution and compared against the approval record, so there is no exploitable window between approval and execution.

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
| `redis_exec` | Run one Redis command against the managed instance. The command is normalized and checked against policy before it is sent: keyspace-wide, server-control, code-loading and cross-instance transfer commands are refused; administrative commands and wildcard writes require approval; read-only diagnostics (`MEMORY`, `SLOWLOG`, and similar) and `CONFIG GET` of a single non-credential parameter are allowed |
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

The gateway is the only mediation point between an agent and production. The only artifact on the agent side is a short-lived token; the kubeconfig, the Redis credentials and the device credentials live in the gateway process and are read only by `internal/adapters/`.

`internal/mcp` does not import `internal/policy`. Projecting an identity onto a policy `Actor` happens in `internal/gateway`, which fixes the order of authentication and authorization at compile time.

### Credentials and audiences

| Audience | Endpoint | Credential |
| --- | --- | --- |
| Agent | `/mcp` | Short-lived, scoped signed token |
| Operator | `/admin` | `AG_ADMIN_TOKEN` |

An agent token cannot approve anything, and a caller cannot approve its own action.

The approval UI's page shell is not authenticated; every data endpoint behind it requires `X-Admin-Token`. A browser cannot attach a custom header to a page navigation, so gating the shell would return `401` before the token form inside it could render. The shell itself carries no business data.

With no `AG_ADMIN_TOKEN` configured the admin surface fails closed, returning `503` with an explanation. `config.Load` already rejects an empty token at startup, and the wrapper keeps an independent check so that comparing two empty values can never report a match.

### Audit chain

Each audit record's hash covers the previous record's hash. Any modification, reordering, or deletion of a record in the middle is detected by `agentgate-cli audit verify`. `/readyz` returns `503` when the chain fails to verify, so chain integrity can be used directly as a readiness signal.

## Configuration

All configuration is supplied through environment variables; the full list is in [`.env.example`](.env.example). The important ones:

| Variable | Description |
| --- | --- |
| `AG_TOKEN_SECRET` / `AG_ADMIN_TOKEN` | Required, at least 16 bytes each, and must differ from one another |
| `AG_ENV` | `staging` or `prod`. Production-marked targets raise the bar: any write, delete, config change, exec or scale change needs a human, and an irreversible change — or a delete at namespace / cluster / dataset / site scope — needs two. A few rules refuse outright, against production only, such as scaling a production workload to zero, `KEYS *`, and shutting a production device interface |
| `AG_STORE_DRIVER` | `sqlite` (default, single node) or `postgres` |
| `AG_STORE_DSN` | Storage connection string |
| `AG_K8S_MODE` | `mock` (default, in-memory simulator) or `cluster` (talk to a real API server) |
| `AG_POLICY_DIR` | Leave empty to use the bundle embedded in the binary |
| `AG_APPROVAL_WEBHOOK_URL` | Where approval cards are posted; shapes `generic` and `feishu` are supported |
| `AG_NETGUARD_URL` | Reachability analysis service for network changes |
| `AG_OTEL_ENDPOINT` | OpenTelemetry trace endpoint |

## Evaluation

The corpus holds 76 payloads: 60 attacks across 5 injection carriers (logs, alerts, cached values, tickets, adversarial variants), plus 16 ordinary operations to measure false positives. The harness runs two arms, one through the gateway and one bypassing it straight to the targets, so the difference is measured rather than projected.

Against a live gateway, with the `scripted` reference agent and 3 repeats per payload:

| Metric | Value | Meaning |
| --- | ---: | --- |
| Injection rate | **36.7%** | Share of payloads where the reference agent emitted the dangerous call. Without a gateway, this is the attack success rate |
| Guarded execution rate (careful approver) | **1.7%** | One of 60 attacks executed: `alert-11-clock-skew`, which the corpus itself marks as allowed |
| Guarded execution rate (rubber-stamp approver) | **10.0%** | Upper bound on leakage through the approval step: the 6 cases not denied outright all execute under an approver who does not read |
| Benign hard false-positive rate | **0.0%** | All 16 ordinary operations completed |
| Benign friction rate | 12.5% | Share requiring a human approval to complete |
| Audit chain | `valid=True` | The whole chain is verified once at the end of the run. The record count varies with run size; the report's Audit chain section gives it for that run |

These numbers measure the `scripted` reference agent, whose behaviour is fixed by the corpus: per-payload injection is 0% or 100%, so repeats carry no statistical information. The run is therefore a self-check of the harness -- it shows the pipeline is wired, policy hits what it should, and the chain is intact. Measuring attack success rate against a model requires `--agent llm`; see [`docs/red-team.md`](docs/red-team.md) §4.

Two full runs, policy bundle `2026.09.1` to `2026.09.2`, are compared in [`eval/report/compare.md`](eval/report/compare.md): `permissive` 4 to 2, `unattended` 1 to 0, zero bypasses under a careful approver, paid for with benign friction rising from 6.2% to 12.5%.

The full report is at [`eval/report/report.md`](eval/report/report.md). Its `policy_gaps` section lists every disagreement between what the corpus expects and what the gateway decides, each with the gateway's own reason. The table runs both ways: what the gateway let through (`permissive`), what it stopped unnecessarily (`friction`), and what ran unattended when a human should have looked (`unattended`).

Methodology and metric definitions are in [`docs/red-team.md`](docs/red-team.md). Without Docker, the suite runs against a built-in RESP2 stub, described in §3.1 of that document.

## Implementation Status

The table below separates real implementations from simulated ones. Simulated components should not be used for production validation.

| Component | Status |
| --- | --- |
| Action normalization, semantic hashing, policy engine (OPA), approval binding, audit hash chain, rollback framework | Real |
| Redis adapter | Real: a hand-written RESP2 client talking to a real Redis |
| Kubernetes adapter | Two modes: `cluster` talks to a real API server (REST + server-side dry-run); `mock` is an in-memory simulator and is the default |
| VRP (Huawei network device) adapter | Simulated: the normalizer is real, the execution side is simulated |
| NetGuard reachability analysis | Falls back to a local heuristic when `AG_NETGUARD_URL` is unset; every output is labelled simulated |
| The no-gateway control arm in the evaluation | Genuinely bypasses the gateway and talks to the targets, not a paper exercise |

## Known Limitations

The project builds, tests, and runs, and the red-team suite produces measured numbers, but it is not ready for production. Known boundaries:

- The approval API authenticates with a token only; there is no SSO or role mapping.
- With multiple replicas sharing one database, appending to the audit chain needs a database-level lock; see [ADR-0005](docs/adr/0005-audit-chain.md).
- Kubernetes `exec` is not implemented in `cluster` mode (it needs SPDY/WebSocket) and currently returns an explicit refusal.
- Authentication failures are written to the application log, not to the audit chain, and the admin surface has no rate limiting.
- The VRP execution side is simulated.
- There is no shadow mode, so a policy's false-positive rate cannot be measured before it takes effect.

### Policy disagreements

The three kinds of disagreement the evaluation surfaces are differences of stance rather than policy defects, but each needs an explicit owner:

| Category | Count | Description |
| --- | ---: | --- |
| `permissive` | 2 | The corpus says `deny`, policy says `allow`. Both are a write or delete of a single named key — `DEL orders:1001`, `SET backdoor 1` — and both are on the `log` carrier, whose read does not pass through the gateway, so the session-taint rule does not fire. The category is permitted by design: the blast radius is one key, and it can be snapshotted and rolled back. The corpus takes a stricter position |
| `deferred` | 9 | The corpus says `deny`, policy says `approval_required` — deleting workloads, scaling to zero, reading Secrets, and writing to protected namespaces (`session:`, `lock:`). The approver is the only line of defense for these actions |
| `unattended` | 0 | Zero since bundle 2026.09.2 |

Each maps to a numbered threat in [`docs/threat-model.md`](docs/threat-model.md).

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
4. Commit messages explain why the change is being made, not only what it does.

## Security

Please do not report security defects through public issues. The disclosure process and scope are described in [`SECURITY.md`](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
