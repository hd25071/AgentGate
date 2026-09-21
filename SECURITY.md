# Security Policy

AgentGate is a security control, so a defect in it is not an ordinary bug: it is
a hole in the thing that is supposed to be holding the line. Reports are taken
seriously and handled as privately as the reporter wants.

## Supported Versions

This project has not cut a `1.0` release. Only the tip of `main` is supported;
there are no maintenance branches and no backports. If you are running a fork or
a pinned commit, reproduce against the current `main` before reporting.

## Reporting a Vulnerability

**Please do not open a public issue for a security defect.**

Use GitHub's private vulnerability reporting on this repository
(*Security* → *Advisories* → *Report a vulnerability*). That channel keeps the
report, the discussion, and the eventual fix private until a patch is available.

If you cannot use GitHub advisories, open a public issue that says only that you
have a security report and would like a private channel — with no technical
detail — and a maintainer will follow up.

### What to include

A useful report gets triaged far faster. Please include:

- The commit or tag you tested against.
- The gateway configuration that matters: `AG_ENV`, `AG_K8S_MODE`,
  `AG_STORE_DRIVER`, and whether a policy bundle was loaded from disk.
- The exact tool call or HTTP request, and the token scopes the caller held.
- What the gateway decided, and what you believe it should have decided.
- The relevant audit records (`agentgate-cli audit tail`, or the `request_id`),
  if the call reached that stage.

A proof of concept is welcome but not required. A precise description of the
trust boundary you crossed is more valuable than a working exploit.

### Disclosure timeline

Acknowledged within **3 business days**. An initial assessment — accepted,
duplicate, or not a vulnerability, with reasoning — within **10 business days**.
Fix timelines depend on severity and on whether a safe mitigation can ship
sooner than the root-cause fix. Credit is given in the advisory unless you ask
otherwise.

## In Scope

The following are exactly the properties the project claims to provide. A break
in any of them is a vulnerability:

| Property | Where it is enforced |
| --- | --- |
| An action that policy denies cannot be executed, however the request is spelled | `internal/action/`, `policies/` |
| Normalization is total and deterministic: equivalent inputs yield the same `Action` and the same SHA-256 hash | `internal/action/` |
| An approval authorizes one specific action and nothing else (no TOCTOU between approval and execution) | `internal/approval/`, `internal/executor/` |
| The audit chain detects modification, reordering, or deletion of any record, including the head | `internal/store/` |
| Credentials held by adapters do not reach the agent, the response body, or the audit log | `internal/adapters/`, `internal/mcp/` |
| An agent token cannot approve an action, and a caller cannot approve its own | `internal/gateway/admin.go` |
| A failure anywhere in the pipeline fails closed, never open | `internal/policy/`, `internal/gateway/` |

Authentication and authorization bypass, request smuggling into the MCP
transport, SSRF through the preview or NetGuard path, and injection into the
approval webhook payload are all in scope.

## Out of Scope

The following are known and documented boundaries, not vulnerabilities. See
[README.md](README.md) and [`docs/threat-model.md`](docs/threat-model.md).

- **The simulated components.** The VRP executor, the in-memory Kubernetes
  adapter (`AG_K8S_MODE=mock`), and the local NetGuard heuristic are simulators.
  Attacking them demonstrates nothing about the gateway.
- **Anything requiring `AG_ADMIN_TOKEN`, the database, or root on the gateway
  host.** Those are the highest trust level by design. A report that starts from
  "the attacker already has the admin token" is describing the threat model, not
  finding a defect — it may still be worth discussing, but as an issue, not an
  advisory.
- **The evaluation harness.** `eval/` is test tooling. It is run by operators on
  their own machine and is not part of the deployed trust boundary.
- **Missing hardening that is already listed as a known gap** in the README's
  status section, unless you can show the gap is materially worse than
  documented.
- **Resource exhaustion with no privilege boundary crossed**, such as
  authenticated callers growing the audit chain by making requests.

## Handling Secrets in a Report

Do not paste real credentials, tokens, kubeconfigs, or production audit records
into a report. Redact them, or reproduce against the `mock` adapters. If a
leaked credential is unavoidable to make the point, say so first and give a
maintainer a chance to set up a safer channel.
