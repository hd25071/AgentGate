package agentgate.k8s

import rego.v1

# ---------------------------------------------------------------------------
# Kubernetes risk tiering.
#
# The normalizer lifts pod-security and RBAC fields out of the manifest; these
# rules decide. Note that a manifest which *looks* narrow can still be
# cluster-wide -- a ClusterRoleBinding with a wildcard rule is the classic
# example, and that is why the rules read `rbac_wildcard` rather than the name.
# ---------------------------------------------------------------------------

protected_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

# Kinds whose deletion removes infrastructure rather than an application.
infrastructure_kinds := {
	"namespace",
	"node",
	"persistentvolume",
	"customresourcedefinition",
	"apiservice",
	"validatingwebhookconfiguration",
	"mutatingwebhookconfiguration",
	"storageclass",
}

# Kinds that hold stateful data; deleting one is effectively a data loss event.
stateful_kinds := {
	"persistentvolumeclaim",
	"statefulset",
	"mysqlcluster",
	"postgresql",
	"redis",
	"rediscluster",
	"kafka",
	"clickhouse",
	"etcdcluster",
	"elasticsearch",
}

workload_kinds := {"deployment", "daemonset", "statefulset", "job", "cronjob", "pod", "replicaset"}

deny contains reason if {
	input.action.verb == "delete"
	k := input.action.args.kind_lower
	k in infrastructure_kinds
	reason := sprintf("k8s: deleting a %s removes infrastructure, not an application", [input.action.args.kind])
}

deny contains reason if {
	input.action.verb == "delete"
	k := input.action.args.kind_lower
	k in stateful_kinds
	reason := sprintf("k8s: deleting a %s destroys persistent state", [input.action.args.kind])
}

deny contains reason if {
	input.action.resource.namespace in protected_namespaces
	input.action.verb in {"write", "delete", "exec", "scale"}
	reason := sprintf("k8s: %s against the control-plane namespace %s", [input.action.verb, input.action.resource.namespace])
}

deny contains reason if {
	input.action.args.rbac_escalation == true
	input.action.args.rbac_wildcard == true
	reason := "k8s: this RBAC object grants wildcard verbs/resources"
}

deny contains reason if {
	input.action.args.rbac_cluster_admin == true
	reason := sprintf("k8s: this binding grants the %q role, which is cluster-admin by another name",
		[input.action.args.rbac_role_ref])
}

# The argument name drives the request path; the manifest name drives the object
# identity. A mismatch means a reviewer reading the approval card and the API
# server acting on the request are looking at different objects.
deny contains reason if {
	input.action.args.manifest_name_mismatch == true
	reason := sprintf("k8s: the request names %q but the manifest declares %q",
		[input.action.args.argument_name, input.action.args.manifest_name])
}

deny contains reason if {
	input.action.args.dangerous_capabilities == true
	reason := sprintf("k8s: container adds kernel capabilities %v", [input.action.args.capabilities_add])
}

deny contains reason if {
	input.action.args.privileged == true
	input.action.resource.namespace in protected_namespaces
	reason := "k8s: privileged container inside a control-plane namespace"
}

deny contains reason if {
	input.action.args.host_path_sensitive == true
	reason := sprintf("k8s: hostPath volume mounts %s from the node filesystem", [input.action.args.host_path])
}

deny contains reason if {
	input.action.args.scale_to_zero == true
	input.action.blast_radius.production == true
	reason := "k8s: scaling a production workload to zero is an outage, use an approval-gated rollout"
}

deny contains reason if {
	input.action.args.exec_in_system_ns == true
	reason := "k8s: exec into a control-plane pod is never a routine diagnostic"
}

# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

approval contains reason if {
	input.action.verb == "delete"
	input.action.args.kind_lower in workload_kinds
	reason := sprintf("k8s: deleting %s/%s", [input.action.resource.namespace, input.action.resource.name])
}

approval contains reason if {
	input.action.verb == "exec"
	reason := sprintf("k8s: exec into %s/%s runs an arbitrary process in the live pod",
		[input.action.resource.namespace, input.action.resource.name])
}

approval contains reason if {
	input.action.verb == "scale"
	reason := sprintf("k8s: scaling %s/%s to %v replicas",
		[input.action.resource.namespace, input.action.resource.name, input.action.args.replicas])
}

approval contains reason if {
	input.action.verb == "write"
	reason := sprintf("k8s: applying %s/%s changes a live workload",
		[input.action.resource.namespace, input.action.resource.name])
}

approval contains reason if {
	input.action.verb == "read"
	input.action.args.kind_lower == "secret"
	reason := "k8s: reading a Secret hands production credentials to the Agent"
}

approval contains reason if {
	input.action.args.rbac_escalation == true
	reason := "k8s: RBAC objects change who can do what"
}

approval contains reason if {
	input.action.args.privileged == true
	reason := "k8s: privileged container escapes the pod sandbox"
}

approval contains reason if {
	input.action.args.host_path_volume == true
	reason := sprintf("k8s: hostPath volume %s reaches the node filesystem", [input.action.args.host_path])
}

approval contains reason if {
	input.action.args.host_network == true
	reason := "k8s: hostNetwork removes the pod network boundary"
}

approval contains reason if {
	input.action.args.host_pid == true
	reason := "k8s: hostPID exposes every process on the node"
}

flags contains reason if {
	input.action.args.image_latest_tag == true
	reason := "k8s: image uses a mutable tag"
}

flags contains reason if {
	input.action.args.no_resource_limits == true
	reason := "k8s: container declares no resource limits"
}

flags contains reason if {
	input.action.args.run_as_root_allowed == true
	reason := "k8s: container may run as root"
}

flags contains reason if {
	input.action.args.allow_privilege_escalation == true
	reason := "k8s: allowPrivilegeEscalation is not disabled"
}

flags contains reason if {
	input.action.args.matches_all_pods == true
	reason := "k8s: selector matches every pod in the namespace"
}

flags contains reason if {
	input.action.blast_radius.scope == "cluster"
	reason := "k8s: action is cluster-scoped"
}

# ---------------------------------------------------------------------------
# Allow reasons
# ---------------------------------------------------------------------------

allow contains reason if {
	input.action.verb == "read"
	not input.action.args.kind_lower == "secret"
	reason := sprintf("k8s: reading %s %s/%s does not change cluster state",
		[input.action.args.kind, input.action.resource.namespace, input.action.resource.name])
}

allow contains reason if {
	input.action.verb == "read"
	input.action.args.kind_lower == "secret"
	reason := "k8s: reading a Secret is allowed only with a human in the loop; see the approval rules"
}

allow contains reason if {
	input.action.verb in {"write", "scale", "delete"}
	input.action.blast_radius.scope in {"object", "key"}
	input.action.blast_radius.affected <= 1
	reason := sprintf("k8s: %s on a single %s is bounded to one object and the gateway snapshots it first",
		[input.action.verb, input.action.args.kind])
}
