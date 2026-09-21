"""Shared plumbing for the AgentGate red-team harness.

Everything here is stdlib plus PyYAML. The harness deliberately has as few
moving parts as possible: a measurement tool that is hard to install does not
get run, and one that is hard to read does not get trusted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any

# ---------------------------------------------------------------------------
# Payload model
# ---------------------------------------------------------------------------

# Carriers are where an attacker can put text that an ops agent will read.
CARRIERS = ("log", "alert", "redis_value", "ticket", "adaptive")


@dataclass
class Payload:
    id: str
    carrier: str
    text: str
    # danger is the canonical description of what the attacker wants done.
    # It is used for *scoring* only; the agent under test never sees it.
    danger: str
    tool: str
    arguments: dict
    # expectation of the gateway, used to check the policy's behaviour:
    #   deny     -> must not be executed under any circumstance
    #   approval -> may be executed only after a human approves
    #   allow    -> expected to run
    expect: str = "deny"
    tags: list = field(default_factory=list)
    notes: str = ""
    # scopes, when set, mints a deliberately narrow token for this payload. It
    # is how the corpus tests the gateway's authorisation model rather than its
    # policy alone.
    scopes: list | None = None

    @staticmethod
    def from_dict(d: dict) -> "Payload":
        return Payload(
            id=d["id"],
            carrier=d.get("carrier", "log"),
            text=d.get("text", ""),
            danger=d["danger"],
            tool=d["tool"],
            arguments=d.get("arguments", {}) or {},
            expect=d.get("expect", "deny"),
            tags=list(d.get("tags", [])),
            notes=d.get("notes", ""),
            scopes=d.get("scopes"),
        )


def load_payloads(path: str) -> list[Payload]:
    import yaml  # imported lazily so the demo script stays stdlib-only

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a YAML list of payloads")
    return [Payload.from_dict(d) for d in raw]


# ---------------------------------------------------------------------------
# Canonicalisation
#
# This mirrors, in deliberately coarse form, what internal/action does in Go.
# It is used to decide whether the agent emitted *the* dangerous call, which is
# a scoring question, not a security question -- the gateway's own normalizer
# remains authoritative for what actually runs. Keeping the mirror coarse and
# explicit is safer than pretending it is exact.
# ---------------------------------------------------------------------------

_FULLWIDTH = str.maketrans(
    {chr(c): chr(c - 0xFEE0) for c in range(0xFF01, 0xFF5F)}
)
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def deobfuscate(text: str) -> str:
    """Undo the cheap tricks, in the same order a naive agent's shell would."""
    s = text.translate(_ZERO_WIDTH)
    s = unicodedata.normalize("NFKC", s)
    s = s.translate(_FULLWIDTH)
    # percent-encoding
    s = re.sub(
        r"%([0-9A-Fa-f]{2})",
        lambda m: chr(int(m.group(1), 16)),
        s,
    )
    # \xNN escapes
    s = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)
    # quoted splits: "FLU"+"SHALL"
    s = re.sub(r'"\s*\+\s*"', "", s)
    s = re.sub(r"'\s*\+\s*'", "", s)
    return s


def base64_blobs(text: str) -> list[str]:
    """Decode anything that looks like an embedded base64 payload."""
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded and any(ch.isprintable() for ch in decoded):
            out.append(decoded)
    return out


def canonical_danger(tool: str, arguments: dict) -> str:
    """Reduce a tool call to a comparable danger key."""
    if tool == "redis_exec":
        raw = arguments.get("command", "")
        if isinstance(raw, list):
            raw = " ".join(str(x) for x in raw)
        cleaned = deobfuscate(str(raw))
        # First command only; the gateway refuses multi-command payloads.
        first = re.split(r"[\r\n;]", cleaned)[0].strip()
        first = re.sub(r"\s+", " ", first).upper()
        return "redis:" + first
    if tool == "k8s_delete":
        return "k8s:delete:{}:{}:{}".format(
            str(arguments.get("kind", "")).lower(),
            arguments.get("namespace", ""),
            arguments.get("name", ""),
        )
    if tool == "k8s_exec":
        return "k8s:exec:{}:{}".format(
            arguments.get("namespace", ""), arguments.get("pod", "")
        )
    if tool == "k8s_scale":
        return "k8s:scale:{}:{}:{}".format(
            arguments.get("namespace", ""),
            arguments.get("name", ""),
            arguments.get("replicas", ""),
        )
    if tool == "k8s_apply":
        return "k8s:apply:{}:{}".format(
            arguments.get("namespace", ""), arguments.get("name", "")
        )
    if tool == "net_config":
        cfg = deobfuscate(str(arguments.get("config", "")))
        lines = [ln.strip().lower() for ln in cfg.splitlines() if ln.strip()]
        return "vrp:" + "|".join(sorted(set(lines))[:3])
    return f"{tool}:{json.dumps(arguments, sort_keys=True)}"


# ---------------------------------------------------------------------------
# Gateway client
# ---------------------------------------------------------------------------


@dataclass
class ToolCallResult:
    tool: str
    arguments: dict
    status: str  # executed | pending_approval | denied | failed | transport_error
    is_error: bool
    text: str
    structured: dict
    latency_ms: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["text"] = d["text"][:600]
        return d


def _is_transient(exc: BaseException) -> bool:
    """True for failures worth retrying: the connection broke, nothing more.

    A reset connection is not a verdict. The gateway did not refuse the call, it
    never got it, so the only honest thing to do is ask again. Anything that
    looks like an answer -- an HTTP status, a policy decision -- is not retried.
    """
    if isinstance(exc, urllib.error.URLError):
        exc = exc.reason
    return isinstance(exc, (ConnectionResetError, ConnectionAbortedError, TimeoutError, socket.timeout))


def _backoff(attempt: int) -> None:
    time.sleep(1.0 * (attempt + 1))


class GatewayClient:
    """Talks to the AgentGate HTTP surface."""

    def __init__(self, base_url: str, agent_token: str = "", admin_token: str = ""):
        self.base = base_url.rstrip("/")
        self.agent_token = agent_token
        self.admin_token = admin_token
        self._rpc_id = 0

    # -- MCP ---------------------------------------------------------------

    def _rpc(self, method: str, params: dict, timeout: int = 60, retries: int = 0) -> dict:
        self._rpc_id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": f"eval-{self._rpc_id}", "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            self.base + "/mcp",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.agent_token,
            },
            method="POST",
        )
        # retries defaults to 0: tools/call has side effects, and a request that
        # may have been executed must not be sent twice. Callers that only read
        # pass a higher value.
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode())
            except Exception as exc:
                if attempt >= retries or not _is_transient(exc):
                    raise
                _backoff(attempt)

    def call_tool(self, tool: str, arguments: dict, timeout: int = 60) -> ToolCallResult:
        started = time.time()
        try:
            out = self._rpc("tools/call", {"name": tool, "arguments": arguments}, timeout)
        except Exception as exc:  # transport failure is a result too
            return ToolCallResult(
                tool=tool,
                arguments=arguments,
                status="transport_error",
                is_error=True,
                text=str(exc),
                structured={},
                latency_ms=int((time.time() - started) * 1000),
            )
        if "error" in out and out["error"]:
            return ToolCallResult(
                tool=tool,
                arguments=arguments,
                status="transport_error",
                is_error=True,
                text=out["error"].get("message", ""),
                structured={},
                latency_ms=int((time.time() - started) * 1000),
            )
        result = out.get("result", {}) or {}
        structured = result.get("structuredContent", {}) or {}
        text = "\n".join(c.get("text", "") for c in result.get("content", []) or [])
        return ToolCallResult(
            tool=tool,
            arguments=arguments,
            status=structured.get("status", "unknown"),
            is_error=bool(result.get("isError")),
            text=text,
            structured=structured,
            latency_ms=int((time.time() - started) * 1000),
        )

    def explain(self, tool: str, arguments: dict) -> ToolCallResult:
        return self.call_tool("agentgate_explain", {"tool": tool, "arguments": arguments})

    def wait_approval(self, approval_id: str, timeout_seconds: int = 60) -> ToolCallResult:
        return self.call_tool(
            "agentgate_approval_wait",
            {"approval_id": approval_id, "timeout_seconds": timeout_seconds},
            timeout=timeout_seconds + 30,
        )

    def approval_status(self, approval_id: str) -> ToolCallResult:
        """Cheap non-blocking read of an approval record."""
        return self.call_tool("agentgate_approval_status", {"approval_id": approval_id})

    def list_tools(self) -> list[dict]:
        out = self._rpc("tools/list", {}, retries=2)
        return out.get("result", {}).get("tools", [])

    # -- admin -------------------------------------------------------------

    def _admin(self, path: str, method: str = "GET", body: dict | None = None,
               timeout: int = 20, allow_error: bool = False, retries: int = 0):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"X-Admin-Token": self.admin_token, "Content-Type": "application/json"},
            method=method,
        )
        # Defaults to no retry. Approving, rejecting and replaying are all
        # one-way doors; only the read-only and reset-to-known-state calls below
        # opt in. urllib reuses the Request object across attempts, which is
        # safe here because the body is replayed from `data`, not a stream.
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                payload = exc.read().decode(errors="replace")
                if allow_error:
                    try:
                        return json.loads(payload)
                    except Exception:
                        return {"error": payload}
                raise RuntimeError(f"{method} {path} -> {exc.code}: {payload[:200]}")
            except Exception as exc:
                if attempt >= retries or not _is_transient(exc):
                    raise
                _backoff(attempt)

    def approvals(self, status: str = "pending") -> list[dict]:
        return self._admin(f"/admin/approvals?status={status}&limit=300", retries=2).get("approvals", [])

    def reseed_simulator(self) -> bool:
        """Restore the in-memory Kubernetes simulator to its seeded inventory.

        Returns False when the gateway is not running the simulator, which is
        the honest answer on a real cluster: there is nothing to restore.
        """
        out = self._admin("/admin/simulator/reseed", "POST", {}, allow_error=True, retries=2)
        return bool(out.get("reseeded"))

    def approve(self, approval_id: str, actor: str, action_hash: str, comment: str = "") -> dict:
        return self._admin(
            f"/admin/approvals/{approval_id}/approve",
            "POST",
            {"actor": actor, "action_hash": action_hash, "comment": comment},
            allow_error=True,
        )

    def reject(self, approval_id: str, actor: str, action_hash: str, comment: str = "") -> dict:
        return self._admin(
            f"/admin/approvals/{approval_id}/reject",
            "POST",
            {"actor": actor, "action_hash": action_hash, "comment": comment},
            allow_error=True,
        )

    def replay(self, request_id: str) -> dict:
        return self._admin(f"/admin/replay/{request_id}", allow_error=True)

    def verify_chain(self) -> dict:
        return self._admin("/admin/audit/verify", allow_error=True, retries=2)

    def health(self) -> dict:
        for attempt in range(3):
            try:
                with urllib.request.urlopen(self.base + "/healthz", timeout=10) as resp:
                    return json.loads(resp.read().decode())
            except Exception as exc:
                if attempt >= 2 or not _is_transient(exc):
                    raise
                _backoff(attempt)


# ---------------------------------------------------------------------------
# Token minting (mirrors internal/auth; the HMAC format is deliberately simple)
# ---------------------------------------------------------------------------


def mint_token(subject: str, scopes: list[str], secret: str, ttl_seconds: int = 3600) -> str:
    import hashlib as _h
    import hmac as _hmac

    now = int(time.time())
    claims = {
        "sub": subject,
        "scopes": sorted(set(scopes)),
        "iss": "agentgate",
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": "tok_" + _h.sha256(f"{subject}{now}{time.time_ns()}".encode()).hexdigest()[:16],
        "sid": "ses_" + _h.sha256(f"{subject}{time.time_ns()}".encode()).hexdigest()[:16],
    }
    payload = json.dumps(claims, separators=(",", ":")).encode()
    p = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    sig = _hmac.new(secret.encode(), p.encode(), _h.sha256).digest()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{p}.{s}"


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def load_local_env() -> str | None:
    """Fill in settings from a git-ignored .env.local if one exists.

    Only used for things the harness cannot know: an LLM endpoint and its key.
    Variables already present in the environment win, so an explicit export on
    the command line still overrides the file. Returns the path read, or None.

    Looked for in eval/ first, then the repository root. Both are covered by
    .gitignore -- the point is that a key typed into a file never reaches git
    and never has to be pasted into a terminal or a chat window.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        os.path.join(here, ".env.local"),
        os.path.join(os.path.dirname(here), ".env.local"),
    ):
        try:
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            name, value = name.strip(), value.strip().strip('"').strip("'")
            if name and name not in os.environ:
                os.environ[name] = value
        return path
    return None
