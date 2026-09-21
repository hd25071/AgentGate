package action

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// K8sNormalizer collapses the kubectl-shaped tools into Actions.
//
// One normalizer serves five tools (get/apply/delete/exec/scale) because they
// differ only in the verb and in which manifest fields matter.
type K8sNormalizer struct{}

func (K8sNormalizer) Tool() string { return "k8s.*" }

// k8sTools lists every tool name this normalizer accepts.
var k8sTools = map[string]Verb{
	"k8s_get":    VerbRead,
	"k8s_apply":  VerbWrite,
	"k8s_delete": VerbDelete,
	"k8s_exec":   VerbExec,
	"k8s_scale":  VerbScale,
}

// clusterScopedKinds are namespaced nowhere; touching them affects the whole
// cluster regardless of how narrow the name looks.
var clusterScopedKinds = map[string]bool{
	"namespace": true, "node": true, "persistentvolume": true,
	"clusterrole": true, "clusterrolebinding": true, "customresourcedefinition": true,
	"storageclass": true, "mutatingwebhookconfiguration": true,
	"validatingwebhookconfiguration": true, "priorityclass": true,
	"apiservice": true, "runtimeclass": true, "csidriver": true,
}

// rbacEscalationKinds can grant arbitrary permissions.
var rbacEscalationKinds = map[string]bool{
	"clusterrolebinding": true, "rolebinding": true, "clusterrole": true, "role": true,
}

func (K8sNormalizer) Normalize(args map[string]any, tgt Target) (*Action, error) {
	tool, _ := args["_tool"].(string)
	verb, ok := k8sTools[tool]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported k8s tool %q", ErrInvalidArgs, tool)
	}

	kind := strings.TrimSpace(str(args["kind"]))
	namespace := strings.TrimSpace(str(args["namespace"]))
	name := strings.TrimSpace(str(args["name"]))
	manifest, err := parseManifest(args["manifest"])
	if err != nil {
		return nil, err
	}

	// A manifest carries kind/namespace/name authoritatively when supplied.
	if manifest != nil {
		if kind == "" {
			kind = strings.TrimSpace(str(manifest["kind"]))
		}
		md, _ := manifest["metadata"].(map[string]any)
		if md != nil {
			if namespace == "" {
				namespace = strings.TrimSpace(str(md["namespace"]))
			}
			if name == "" {
				name = strings.TrimSpace(str(md["name"]))
			}
		}
	}

	// exec addresses a pod and its MCP schema does not ask the caller for a
	// kind (kubectl exec does not either), so the kind is inferred here rather
	// than demanded. Demanding it would make every exec call arrive
	// unparseable, which the gateway refuses -- i.e. the tool would simply not
	// work, and an operator would conclude the gateway is broken.
	if kind == "" && verb == VerbExec {
		kind = "Pod"
	}
	if kind == "" {
		return nil, fmt.Errorf("%w: k8s tool requires a resource kind", ErrInvalidArgs)
	}
	if name == "" && manifest == nil && verb != VerbExec {
		return nil, fmt.Errorf("%w: k8s tool requires a resource name", ErrInvalidArgs)
	}
	if namespace == "" {
		namespace = "default"
	}

	kl := strings.ToLower(kind)
	clusterScoped := clusterScopedKinds[kl]

	out := map[string]any{
		"op":              tool[4:], // strip "k8s_"
		"kind":            kind,
		"kind_lower":      kl,
		"namespace":       namespace,
		"name":            name,
		"cluster_scoped":  clusterScoped,
		"is_delete":       verb == VerbDelete,
		"is_exec":         verb == VerbExec,
		"is_scale":        verb == VerbScale,
		"rbac_escalation": rbacEscalationKinds[kl],
	}

	if manifest != nil {
		raw, _ := json.Marshal(manifest)
		out["manifest_bytes"] = len(raw)
		// A digest over the *semantic* object, not over the bytes as received.
		// Everything else lifted out of a manifest is a feature ("privileged",
		// "host_path") or a size; without this, two manifests that differ only
		// in a field policy does not read -- and happen to be the same length
		// -- produce the same action hash, and one approval would cover both.
		// json.Marshal sorts map keys, so reformatting and reordering do not
		// move the digest while any change in content does.
		sum := sha256.Sum256(raw)
		out["manifest_digest"] = hex.EncodeToString(sum[:])
		analyzeManifest(manifest, out)

		// The argument name and the manifest name must agree. They are used in
		// different places -- the URL path comes from the argument, the object
		// identity comes from the manifest -- so a mismatch means the reviewer
		// and the API server are looking at different objects.
		if md, ok := manifest["metadata"].(map[string]any); ok {
			mName := strings.TrimSpace(str(md["name"]))
			if argName := strings.TrimSpace(str(args["name"])); argName != "" && mName != "" && mName != argName {
				out["manifest_name_mismatch"] = true
				out["manifest_name"] = mName
				out["argument_name"] = argName
			}
			if mNs := strings.TrimSpace(str(md["namespace"])); mNs != "" && mNs != namespace {
				out["manifest_namespace_mismatch"] = true
			}
		}
	}

	if verb == VerbExec {
		cmd := stringSlice(args["command"])
		out["exec_command"] = strings.Join(cmd, " ")
		out["set:exec_argv"] = cmd
		out["exec_in_system_ns"] = namespace == "kube-system"
		out["container"] = str(args["container"])
		out["pod"] = str(args["pod"])
		if name == "" {
			name = str(args["pod"])
		}
		kind = "Pod"
		kl = "pod"
		out["kind"] = kind
		out["kind_lower"] = kl
	}

	if verb == VerbScale {
		r, ok := toInt(args["replicas"])
		if !ok {
			return nil, fmt.Errorf("%w: k8s_scale requires an integer replicas value", ErrInvalidArgs)
		}
		out["replicas"] = r
		out["scale_to_zero"] = r == 0
	}

	if verb == VerbDelete {
		out["protected_kind"] = kl == "persistentvolumeclaim" || kl == "persistentvolume" ||
			kl == "namespace" || kl == "node" || kl == "customresourcedefinition" ||
			kl == "statefulset" || kl == "database" || kl == "mysqlcluster"
		out["deletes_cluster_scoped"] = clusterScoped
	}

	scope := ScopeObject
	switch {
	case verb == VerbExec:
		scope = ScopeWorkload
	case kl == "namespace":
		scope = ScopeNS
	case clusterScoped:
		scope = ScopeCluster
	case verb == VerbDelete && (kl == "deployment" || kl == "statefulset" || kl == "daemonset"):
		scope = ScopeWorkload
	}

	affected := 1
	if verb == VerbDelete && kl == "namespace" {
		affected = -1
	}
	if verb == VerbScale {
		affected = intOf(out["replicas"])
		if affected == 0 {
			affected = -1
		}
	}

	irreversible := verb == VerbDelete && (kl == "persistentvolumeclaim" || kl == "persistentvolume" || kl == "namespace")

	a := &Action{
		Tool:        tool,
		Target:      tgt,
		Verb:        verb,
		Resource:    Resource{Type: kind, Name: name, Namespace: namespace, Count: affected},
		Args:        out,
		BlastRadius: BlastRadius{Scope: scope, Affected: affected, Irreversible: irreversible, Production: strings.EqualFold(tgt.Env, "prod")},
		Raw:         compactJSON(args, "_tool", "manifest"),
	}
	if manifest != nil {
		raw, _ := json.Marshal(manifest)
		a.Raw = "manifest=" + string(raw)
	}
	if err := a.Seal(); err != nil {
		return nil, err
	}
	return a, nil
}

// analyzeManifest extracts the pod-security and RBAC features that policy
// cares about. Only fields with a security meaning are lifted out.
func analyzeManifest(m map[string]any, out map[string]any) {
	spec, _ := m["spec"].(map[string]any)
	if spec == nil {
		if r, ok := m["rules"]; ok {
			out["rbac_rules"] = len(anySlice(r))
			out["rbac_wildcard"] = rulesAreWildcard(r)
		}
		// A binding is dangerous because of what it binds to, not because of
		// the rules written in it -- a ClusterRoleBinding has no rules at all.
		if roleRef, ok := m["roleRef"].(map[string]any); ok {
			name := strings.ToLower(strings.TrimSpace(str(roleRef["name"])))
			out["rbac_role_ref"] = name
			if name == "cluster-admin" || name == "admin" || name == "edit" {
				out["rbac_cluster_admin"] = true
			}
		}
		return
	}

	if v, ok := toInt(spec["replicas"]); ok {
		out["replicas"] = v
	}
	if sel, ok := spec["selector"].(map[string]any); ok {
		if isWildcardSelector(sel) {
			out["matches_all_pods"] = true
		}
	}
	// A workload spec with no selector at all (e.g. a Service or a
	// NetworkPolicy with an empty podSelector) also matches everything.
	if netpol, ok := spec["podSelector"].(map[string]any); ok {
		if len(netpol) == 0 {
			out["matches_all_pods"] = true
		}
	}

	tmpl, _ := spec["template"].(map[string]any)
	if tmpl == nil {
		return
	}
	podSpec, _ := tmpl["spec"].(map[string]any)
	if podSpec == nil {
		return
	}

	if b, ok := podSpec["hostNetwork"].(bool); ok && b {
		out["host_network"] = true
	}
	if b, ok := podSpec["hostPID"].(bool); ok && b {
		out["host_pid"] = true
	}
	if b, ok := podSpec["hostIPC"].(bool); ok && b {
		out["host_ipc"] = true
	}

	for _, v := range anySlice(podSpec["volumes"]) {
		vm, _ := v.(map[string]any)
		if hostPath, ok := vm["hostPath"].(map[string]any); ok {
			out["host_path_volume"] = true
			p := str(hostPath["path"])
			out["host_path"] = p
			if p == "/" || strings.HasPrefix(p, "/var/") || strings.HasPrefix(p, "/etc") {
				out["host_path_sensitive"] = true
			}
		}
	}

	privileged := false
	capAdd := map[string]bool{}
	for _, c := range anySlice(podSpec["containers"]) {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		if sc, ok := cm["securityContext"].(map[string]any); ok {
			if b, ok := sc["privileged"].(bool); ok && b {
				privileged = true
			}
			if b, ok := sc["allowPrivilegeEscalation"].(bool); ok && b {
				out["allow_privilege_escalation"] = true
			}
			if b, ok := sc["runAsNonRoot"].(bool); ok && !b {
				out["run_as_root_allowed"] = true
			}
			if caps, ok := sc["capabilities"].(map[string]any); ok {
				for _, v := range anySlice(caps["add"]) {
					capAdd[strings.ToUpper(str(v))] = true
				}
				for _, v := range anySlice(caps["drop"]) {
					delete(capAdd, strings.ToUpper(str(v)))
				}
			}
		}
		img := str(cm["image"])
		if strings.HasSuffix(img, ":latest") || (img != "" && !strings.Contains(img, ":")) {
			out["image_latest_tag"] = true
		}
		if res, ok := cm["resources"].(map[string]any); ok {
			if _, hasLimits := res["limits"]; !hasLimits {
				out["no_resource_limits"] = true
			}
		} else {
			out["no_resource_limits"] = true
		}
	}
	if len(capAdd) > 0 {
		names := make([]string, 0, len(capAdd))
		for k := range capAdd {
			names = append(names, k)
		}
		sort.Strings(names)
		out["set:capabilities_add"] = names
		out["dangerous_capabilities"] = dangerousCaps(names)
	}
	if privileged {
		out["privileged"] = true
	}
	if podSpec["serviceAccountName"] != nil {
		out["service_account"] = str(podSpec["serviceAccountName"])
	}
}

// dangerousCapabilities are Linux capabilities that, added to a container,
// amount to host compromise. They are denied outright rather than gated.
var dangerousCapabilities = map[string]bool{
	"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "SYS_RAWIO": true,
	"NET_ADMIN": true, "NET_RAW": true, "DAC_READ_SEARCH": true, "DAC_OVERRIDE": true,
	"SETFCAP": true, "SETUID": true, "SETGID": true, "BPF": true,
	"PERFMON": true, "AUDIT_CONTROL": true, "MAC_ADMIN": true, "ALL": true,
}

func dangerousCaps(names []string) bool {
	for _, n := range names {
		if dangerousCapabilities[strings.ToUpper(n)] {
			return true
		}
	}
	return false
}

func isWildcardSelector(sel map[string]any) bool {
	ml, _ := sel["matchLabels"].(map[string]any)
	if len(ml) == 0 {
		return true
	}
	return false
}

func rulesAreWildcard(r any) bool {
	for _, rule := range anySlice(r) {
		rm, _ := rule.(map[string]any)
		if rm == nil {
			continue
		}
		for _, field := range []string{"verbs", "resources", "apiGroups"} {
			for _, v := range anySlice(rm[field]) {
				if str(v) == "*" {
					return true
				}
			}
		}
	}
	return false
}

func parseManifest(v any) (map[string]any, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return t, nil
	case string:
		if strings.TrimSpace(t) == "" {
			return nil, nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(t), &m); err != nil {
			// YAML is not accepted here on purpose: the gateway refuses to run a
			// YAML parser over agent-controlled input for this surface, and an
			// unparseable manifest must fail closed.
			return nil, fmt.Errorf("%w: manifest must be a JSON object: %v", ErrInvalidArgs, err)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("%w: manifest must be an object or JSON string", ErrInvalidArgs)
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return strings.Fields(t)
	default:
		return nil
	}
}

func anySlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case json.Number:
		n, err := t.Int64()
		return int(n), err == nil
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

func intOf(v any) int {
	n, _ := toInt(v)
	return n
}

func compactJSON(m map[string]any, skip ...string) string {
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[s] = true
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		if skipSet[k] {
			continue
		}
		cp[k] = v
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return ""
	}
	return string(b)
}
