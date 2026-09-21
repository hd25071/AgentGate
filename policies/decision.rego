package agentgate.decision

import rego.v1

import data.agentgate.common
import data.agentgate.k8s
import data.agentgate.redis
import data.agentgate.vrp

# ---------------------------------------------------------------------------
# Aggregate verdict.
#
# Sub-packages contribute reasons; this package resolves them into exactly one
# of allow / approval_required / deny. The three branches are mutually
# exclusive by construction, and the `default` is a deny -- a policy bundle
# that fails to load, or an input shape nobody anticipated, must never fall
# through to "allow".
#
# Every aggregation below is gated on the target kind. Without that gate a
# rule written for one subsystem fires on another: `vrp: every device
# configuration change needs a human` was being attached to Redis CONFIG
# changes, because both use verb "config". The verdict happened to be the same,
# but the *reason* was wrong -- and the reason is what a reviewer reads on the
# approval card and what the red-team report prints as the justification. A
# reason from the wrong subsystem is worse than no reason.
# ---------------------------------------------------------------------------

bundle_version := "2026.09.2"

deny_set contains r if { input.action.target.kind == "redis"; r := redis.deny[_] }
deny_set contains r if { input.action.target.kind == "k8s"; r := k8s.deny[_] }
deny_set contains r if { input.action.target.kind == "vrp"; r := vrp.deny[_] }
deny_set contains r if { r := common.deny[_] }

approval_set contains r if { input.action.target.kind == "redis"; r := redis.approval[_] }
approval_set contains r if { input.action.target.kind == "k8s"; r := k8s.approval[_] }
approval_set contains r if { input.action.target.kind == "vrp"; r := vrp.approval[_] }
approval_set contains r if { r := common.approval[_] }

flags_set contains r if { input.action.target.kind == "redis"; r := redis.flags[_] }
flags_set contains r if { input.action.target.kind == "k8s"; r := k8s.flags[_] }
flags_set contains r if { input.action.target.kind == "vrp"; r := vrp.flags[_] }
flags_set contains r if { r := common.flags[_] }

allow_set contains r if { input.action.target.kind == "redis"; r := redis.allow[_] }
allow_set contains r if { input.action.target.kind == "k8s"; r := k8s.allow[_] }
allow_set contains r if { input.action.target.kind == "vrp"; r := vrp.allow[_] }
allow_set contains r if { r := common.allow[_] }

deny_list := sort([r | r := deny_set[_]])
approval_list := sort([r | r := approval_set[_]])
flags_list := sort([r | r := flags_set[_]])
allow_list := sort([r | r := allow_set[_]])

# An allow must explain itself. If no package contributed a positive reason,
# synthesise one from the action's own blast radius rather than emitting an
# empty list: an unexplained yes cannot be argued with or tuned, and a report
# that shows "(no reason returned)" for every permitted action is useless.
#
# Note the field is resource.type, not resource.kind. Reading a field that does
# not exist makes the whole expression undefined, which would drop this branch
# and let the `default result` deny fire -- turning every allow into a deny.
allow_reasons := allow_list if { count(allow_list) > 0 }

allow_reasons := [sprintf("%s %s on %s: blast radius %s, %d affected, irreversible=%v",
	[input.action.target.kind, input.action.verb, input.action.resource.type,
	 input.action.blast_radius.scope, input.action.blast_radius.affected,
	 input.action.blast_radius.irreversible])] if { count(allow_list) == 0 }

dual_required if { common.dual }
dual_required if { redis.dual }
dual_required if { k8s.dual }
dual_required if { vrp.dual }

risk := "critical" if { count(deny_list) > 0 }

risk := "high" if {
	count(deny_list) == 0
	count(approval_list) > 0
}

risk := "medium" if {
	count(deny_list) == 0
	count(approval_list) == 0
	count(flags_list) > 0
}

risk := "low" if {
	count(deny_list) == 0
	count(approval_list) == 0
	count(flags_list) == 0
}

default required_approvals := 0

required_approvals := 2 if {
	dual_required
	count(deny_list) == 0
	count(approval_list) > 0
}

required_approvals := 1 if {
	not dual_required
	count(deny_list) == 0
	count(approval_list) > 0
}

default required_scope_label := "unmapped"

required_scope_label := s if {
	s := common.required_scope
}

default result := {
	"decision": "deny",
	"risk": "unknown",
	"reasons": ["policy produced no verdict: fail closed"],
	"required_approvals": 0,
	"flags": [],
	"required_scope": "unmapped",
	"policy_version": "unloaded",
}

result := {
	"decision": "deny",
	"risk": risk,
	"reasons": deny_list,
	"required_approvals": 0,
	"flags": flags_list,
	"required_scope": required_scope_label,
	"policy_version": bundle_version,
} if {
	count(deny_list) > 0
}

result := {
	"decision": "approval_required",
	"risk": risk,
	"reasons": approval_list,
	"required_approvals": required_approvals,
	"flags": flags_list,
	"required_scope": required_scope_label,
	"policy_version": bundle_version,
} if {
	count(deny_list) == 0
	count(approval_list) > 0
}

result := {
	"decision": "allow",
	"risk": risk,
	"reasons": allow_reasons,
	"required_approvals": 0,
	"flags": flags_list,
	"required_scope": required_scope_label,
	"policy_version": bundle_version,
} if {
	count(deny_list) == 0
	count(approval_list) == 0
}
