package agentgate.common

import rego.v1

# ---------------------------------------------------------------------------
# Scope model
#
# Every action requires exactly one scope, derived from (target.kind, verb).
# Scopes are carried in the short-lived token the gateway issues, never in the
# Agent's own configuration, and the gateway holds the real credentials.
# ---------------------------------------------------------------------------

required_scope := s if {
	input.action.target.kind == "redis"
	input.action.verb == "read"
	s := "redis:read"
}

required_scope := s if {
	input.action.target.kind == "redis"
	input.action.verb in {"write", "exec"}
	s := "redis:write"
}

required_scope := s if {
	input.action.target.kind == "redis"
	input.action.verb == "delete"
	s := "redis:delete"
}

required_scope := s if {
	input.action.target.kind == "redis"
	input.action.verb == "config"
	s := "redis:admin"
}

required_scope := s if {
	input.action.target.kind == "k8s"
	input.action.verb == "read"
	s := "k8s:read"
}

required_scope := s if {
	input.action.target.kind == "k8s"
	input.action.verb in {"write", "scale"}
	s := "k8s:write"
}

required_scope := s if {
	input.action.target.kind == "k8s"
	input.action.verb == "delete"
	s := "k8s:delete"
}

required_scope := s if {
	input.action.target.kind == "k8s"
	input.action.verb == "exec"
	s := "k8s:exec"
}

required_scope := s if {
	input.action.target.kind == "vrp"
	input.action.verb in {"read", "config"}
	s := "vrp:config"
}

required_scope := s if {
	input.action.target.kind == "vrp"
	input.action.verb == "delete"
	s := "vrp:config"
}

# ---------------------------------------------------------------------------
# Deny reasons
# ---------------------------------------------------------------------------

# sealed distinguishes "the gateway's normalizer produced this action" from "a
# value happens to be present".
#
# Writing this as `not input.action.hash` does not work, and fails in the
# dangerous direction: `not` tests for *undefined*, while JSON marshalling
# always emits the key -- an unset hash arrives as the string "" and is
# perfectly well defined, so the negation is false and the rule never fires.
# An unsealed action would then be evaluated like any other. Comparing against
# "" covers both spellings, because an absent key leaves the comparison
# undefined and the negation true.
sealed if {
	input.action.hash != ""
}

# authenticated is the same idea for the caller. An empty subject is not an
# absent subject, and neither one may be treated as a default identity.
authenticated if {
	input.actor.subject != ""
}

deny contains "unknown target kind: fail closed" if {
	not required_scope
}

deny contains "action arrived unsealed (empty hash): refusing to evaluate" if {
	not sealed
}

deny contains reason if {
	s := required_scope
	not s in input.actor.scopes
	reason := sprintf("actor %q lacks required scope %q", [input.actor.subject, s])
}

deny contains "anonymous actor: every tool call must carry an authenticated subject" if {
	not authenticated
}

# Credential-bearing or code-loading capability never travels through the
# gateway, regardless of who asks or how well they argue.
deny contains "target endpoint was supplied by the Agent; endpoints come from gateway config" if {
	input.action.target.endpoint
	not startswith(input.action.target.endpoint, "gw:")
}

# ---------------------------------------------------------------------------
# Approval reasons
# ---------------------------------------------------------------------------

# A rollback-able change to production still deserves a human, but it is not a
# hard no. An irreversible one in production needs two humans.
approval contains "production target: change requires human approval" if {
	input.action.blast_radius.production == true
	input.action.verb in {"write", "delete", "config", "exec", "scale"}
}

dual if {
	input.action.blast_radius.production == true
	input.action.blast_radius.irreversible == true
}

dual if {
	input.action.blast_radius.production == true
	input.action.verb == "delete"
	input.action.blast_radius.scope in {"namespace", "cluster", "dataset", "site"}
}

# ---------------------------------------------------------------------------
# Session taint
#
# Indirect injection needs a read to happen first: the injected text arrives as
# a log line, an alert annotation, a cached value or a ticket body, and every
# one of those is a gateway call the gateway can see. Once a session has read,
# a write proposed in that session may have been suggested by what it read.
#
# The rule is not content inspection. The gateway never tries to decide whether
# a string looks like an instruction -- that is a classifier with no reliable
# answer, and a false negative on it is the whole game. It tracks the data
# flow, which it observes exactly.
#
# The cost is real and accepted: an agent that has read anything is asked for a
# human on every subsequent mutation in that session.
# ---------------------------------------------------------------------------

approval contains reason if {
	input.actor.session_tainted == true
	input.action.verb in {"write", "delete", "config", "exec", "scale"}
	reason := "this session has read content from a target system, so a mutation proposed now may have been suggested by what it read"
}

# Flagged on mutations only. Putting it on reads too would mark every read in
# a tainted session as "medium" risk, and a tier that is always raised carries
# no information.
flags contains "session has read attacker-influenceable content" if {
	input.actor.session_tainted == true
	input.action.verb in {"write", "delete", "config", "exec", "scale"}
}

# ---------------------------------------------------------------------------
# Informational flags
# ---------------------------------------------------------------------------

flags contains "action has unbounded blast radius" if {
	input.action.blast_radius.affected < 0
}

flags contains "action is irreversible" if {
	input.action.blast_radius.irreversible == true
}

# ---------------------------------------------------------------------------
# Allow reasons
#
# An allow is a decision too. "The gateway said yes" with no stated reason is a
# verdict an operator can neither argue with nor tune -- and it is what made the
# first red-team gap table unreadable, because every permitted action showed up
# as "(no reason returned)". Every allow therefore carries at least the scope it
# consumed, and decision.rego guarantees the list is never empty.
# ---------------------------------------------------------------------------

allow contains reason if {
	reason := sprintf("scope %q was required and is held by the caller", [required_scope])
}

allow contains reason if {
	input.action.blast_radius.scope == "key"
	input.action.blast_radius.irreversible == false
	reason := sprintf("blast radius is bounded to %d named object(s) and is reversible", [input.action.blast_radius.affected])
}
