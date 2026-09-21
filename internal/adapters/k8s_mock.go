package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
)

// MockK8sAdapter is an in-memory cluster.
//
// It exists so that the whole pipeline -- normalize, policy, approval, preview,
// snapshot, execute, audit, replay -- can be demonstrated and red-teamed with
// `docker compose up` and no cluster. Every surface that reports on this
// adapter labels it as a simulator; see README "what is real and what is not".
//
// It implements the same interface as K8sAdapter, including exec, because the
// point of the simulator is to give the policy engine something to protect.
type MockK8sAdapter struct {
	cfg K8sConfig

	mu      sync.Mutex
	objects map[string]map[string]any
}

// NewMockK8sAdapter builds a seeded cluster.
func NewMockK8sAdapter(cfg K8sConfig) *MockK8sAdapter {
	if cfg.Name == "" {
		cfg.Name = "k8s-simulator"
	}
	m := &MockK8sAdapter{cfg: cfg, objects: map[string]map[string]any{}}
	m.seed()
	return m
}

func (m *MockK8sAdapter) Kind() action.Kind { return action.KindK8s }
func (m *MockK8sAdapter) Name() string      { return m.cfg.Name }

func key(kind, ns, name string) string {
	return strings.ToLower(kind) + "/" + ns + "/" + name
}

func (m *MockK8sAdapter) put(kind, ns, name string, obj map[string]any) {
	m.objects[key(kind, ns, name)] = obj
}

func (m *MockK8sAdapter) seed() {
	deploy := func(ns, name string, replicas int, image string) map[string]any {
		return map[string]any{
			"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{"app": name}},
			"spec": map[string]any{
				"replicas": replicas,
				"selector": map[string]any{"matchLabels": map[string]any{"app": name}},
				"template": map[string]any{
					"metadata": map[string]any{"labels": map[string]any{"app": name}},
					"spec": map[string]any{
						"containers": []any{map[string]any{"name": name, "image": image,
							"resources": map[string]any{"limits": map[string]any{"cpu": "500m"}}}},
					},
				},
			},
		}
	}
	m.put("Deployment", "default", "web", deploy("default", "web", 3, "nginx:1.27"))
	m.put("Deployment", "payments", "checkout", deploy("payments", "checkout", 6, "checkout:2.4.1"))
	m.put("Deployment", "kube-system", "coredns", deploy("kube-system", "coredns", 2, "coredns:1.11"))

	// Pods. A simulator that knows about Deployments but not their Pods is
	// internally inconsistent, and the inconsistency is not harmless: every
	// pod-scoped action (exec, delete-a-stuck-pod) would fail on a missing
	// object rather than on the thing under test. web-7d9f8c6b4-x2k9m is the
	// one the corpus keeps in Terminating.
	pod := func(ns, name, owner, phase string, ready bool) map[string]any {
		readyStatus := "False"
		if ready {
			readyStatus = "True"
		}
		return map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{
				"name": name, "namespace": ns,
				"labels": map[string]any{"app": owner},
				"ownerReferences": []any{map[string]any{
					"apiVersion": "apps/v1", "kind": "ReplicaSet",
					"name": owner + "-7d9f8c6b4", "controller": true,
				}},
			},
			"spec": map[string]any{
				"nodeName": "node-1",
				"containers": []any{map[string]any{
					"name": owner, "image": owner + ":latest",
					"resources": map[string]any{"limits": map[string]any{"cpu": "500m"}},
				}},
			},
			"status": map[string]any{
				"phase": phase,
				"conditions": []any{map[string]any{
					"type": "Ready", "status": readyStatus,
				}},
			},
		}
	}
	m.put("Pod", "default", "web-7d9f8c6b4-x2k9m", pod("default", "web-7d9f8c6b4-x2k9m", "web", "Terminating", false))
	m.put("Pod", "default", "web-7d9f8c6b4-p4t2q", pod("default", "web-7d9f8c6b4-p4t2q", "web", "Running", true))
	m.put("Pod", "default", "web-7d9f8c6b4-q7m1z", pod("default", "web-7d9f8c6b4-q7m1z", "web", "Running", true))
	m.put("Pod", "payments", "checkout-5c8d7f9b6-h3n8p", pod("payments", "checkout-5c8d7f9b6-h3n8p", "checkout", "Running", true))
	m.put("Pod", "kube-system", "coredns-6d4b75cb6-abcde", pod("kube-system", "coredns-6d4b75cb6-abcde", "coredns", "Running", true))
	m.put("StatefulSet", "payments", "orders-db", map[string]any{
		"apiVersion": "apps/v1", "kind": "StatefulSet",
		"metadata": map[string]any{"name": "orders-db", "namespace": "payments"},
		"spec":     map[string]any{"replicas": 3, "serviceName": "orders-db"},
	})
	m.put("PersistentVolumeClaim", "payments", "orders-db-0", map[string]any{
		"apiVersion": "v1", "kind": "PersistentVolumeClaim",
		"metadata": map[string]any{"name": "orders-db-0", "namespace": "payments"},
		"spec":     map[string]any{"storageClassName": "fast-ssd", "resources": map[string]any{"requests": map[string]any{"storage": "200Gi"}}},
	})
	m.put("Namespace", "", "payments", map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "payments", "labels": map[string]any{"env": "prod"}},
	})
	m.put("Namespace", "", "kube-system", map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "kube-system"},
	})
	m.put("Node", "", "node-1", map[string]any{
		"apiVersion": "v1", "kind": "Node",
		"metadata": map[string]any{"name": "node-1"},
	})
	m.put("Secret", "payments", "db-credentials", map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "db-credentials", "namespace": "payments"},
		"data":     map[string]any{"password": "cGFzc3dvcmQ=", "username": "b3JkZXJz"},
	})
	m.put("ClusterRoleBinding", "", "platform-admin", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
		"metadata": map[string]any{"name": "platform-admin"},
		"roleRef":  map[string]any{"kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "default", "namespace": "payments"}},
	})
	m.put("CustomResourceDefinition", "", "databases.example.com", map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]any{"name": "databases.example.com"},
	})
}

func (m *MockK8sAdapter) Health(ctx context.Context) error { return nil }

func (m *MockK8sAdapter) lookup(kind, ns, name string) (map[string]any, bool) {
	obj, ok := m.objects[key(kind, ns, name)]
	return obj, ok
}

// Snapshot captures the current object.
func (m *MockK8sAdapter) Snapshot(ctx context.Context, a *action.Action) (Snapshot, error) {
	snap := Snapshot{Adapter: m.Name(), TakenAt: time.Now().UnixMilli(), Data: json.RawMessage(`{}`)}
	if a.Verb == action.VerbRead {
		snap.Strategy = "none"
		snap.Note = "read-only action: nothing to roll back"
		return snap, nil
	}
	if a.Verb == action.VerbExec {
		snap.Strategy = "none"
		snap.Note = "exec has no rollback: whatever the process did stands"
		return snap, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	obj, ok := m.lookup(a.ArgString("kind"), a.Resource.Namespace, a.Resource.Name)
	if !ok {
		snap.Strategy = "delete-on-rollback"
		snap.Note = "object does not exist yet; rollback deletes whatever this creates"
		return snap, nil
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return snap, err
	}
	snap.Strategy = "restore-object"
	snap.Data = raw
	snap.Note = "full object captured; rollback re-applies the captured manifest"
	return snap, nil
}

// Preview reports the same findings the real adapter would, without writing.
func (m *MockK8sAdapter) Preview(ctx context.Context, a *action.Action) (PreviewResult, error) {
	out := PreviewResult{Adapter: m.Name(), Supported: true}
	if a.Verb == action.VerbRead {
		out.Impact = "read-only: no state changes"
		return out, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	kind := a.ArgString("kind")
	obj, exists := m.lookup(kind, a.Resource.Namespace, a.Resource.Name)

	switch a.Verb {
	case action.VerbDelete:
		if !exists {
			return out, fmt.Errorf("%s %s/%s does not exist", kind, a.Resource.Namespace, a.Resource.Name)
		}
		out.Impact = fmt.Sprintf("dry-run: %s %s/%s would be deleted", kind, a.Resource.Namespace, a.Resource.Name)
		if kind == "PersistentVolumeClaim" || kind == "Namespace" {
			out.Findings = append(out.Findings, "deletion is irreversible: attached storage is not reclaimed by this action")
		}
		if deps := m.dependents(kind, a.Resource.Namespace, a.Resource.Name); len(deps) > 0 {
			out.Findings = append(out.Findings, "dependent objects: "+strings.Join(deps, ", "))
		}
		return out, nil
	case action.VerbScale:
		cur := 0
		if exists {
			if spec, ok := obj["spec"].(map[string]any); ok {
				cur, _ = spec["replicas"].(int)
			}
		}
		out.Impact = fmt.Sprintf("dry-run: %s/%s would scale %d -> %d", a.Resource.Namespace, a.Resource.Name, cur, a.ArgInt("replicas"))
		if a.ArgInt("replicas") == 0 {
			out.Findings = append(out.Findings, "scaling to zero removes all serving capacity for this workload")
		}
		return out, nil
	default:
		out.Impact = fmt.Sprintf("dry-run: %s %s/%s would be applied", kind, a.Resource.Namespace, a.Resource.Name)
		if !exists {
			out.Findings = append(out.Findings, "object does not exist and would be created")
		}
		if a.ArgBool("privileged") {
			out.Findings = append(out.Findings, "manifest requests a privileged container")
		}
		if a.ArgBool("host_path_volume") {
			out.Findings = append(out.Findings, "manifest mounts a hostPath volume: "+a.ArgString("host_path"))
		}
		out.Findings = append(out.Findings, "simulator dry run: admission controllers are not evaluated")
		return out, nil
	}
}

func (m *MockK8sAdapter) dependents(kind, ns, name string) []string {
	var out []string
	for k := range m.objects {
		parts := strings.SplitN(k, "/", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == ns && parts[2] != name && (kind == "Namespace" || strings.HasPrefix(parts[2], name)) {
			out = append(out, parts[0]+"/"+parts[2])
		}
	}
	sort.Strings(out)
	if len(out) > 6 {
		out = append(out[:6], fmt.Sprintf("... and %d more", len(out)-6))
	}
	return out
}

// Execute mutates the in-memory cluster.
func (m *MockK8sAdapter) Execute(ctx context.Context, a *action.Action) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kind := a.ArgString("kind")
	ns, name := a.Resource.Namespace, a.Resource.Name

	switch a.Verb {
	case action.VerbRead:
		obj, ok := m.lookup(kind, ns, name)
		if !ok {
			return Result{Adapter: m.Name(), Status: "failed", Summary: fmt.Sprintf("%s %s/%s not found", kind, ns, name)},
				fmt.Errorf("not found")
		}
		return Result{Adapter: m.Name(), Status: "ok", Summary: fmt.Sprintf("read %s/%s", ns, name), Output: Sanitize(obj)}, nil

	case action.VerbDelete:
		if _, ok := m.lookup(kind, ns, name); !ok {
			return Result{Adapter: m.Name(), Status: "failed", Summary: "not found"}, fmt.Errorf("%s %s/%s not found", kind, ns, name)
		}
		delete(m.objects, key(kind, ns, name))
		return Result{Adapter: m.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("deleted %s %s/%s (simulator)", kind, ns, name)}, nil

	case action.VerbScale:
		obj, ok := m.lookup(kind, ns, name)
		if !ok {
			return Result{Adapter: m.Name(), Status: "failed", Summary: "not found"}, fmt.Errorf("%s %s/%s not found", kind, ns, name)
		}
		spec, _ := obj["spec"].(map[string]any)
		if spec == nil {
			spec = map[string]any{}
			obj["spec"] = spec
		}
		spec["replicas"] = a.ArgInt("replicas")
		return Result{Adapter: m.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("scaled %s/%s to %d (simulator)", ns, name, a.ArgInt("replicas"))}, nil

	case action.VerbExec:
		argv := a.ArgStrings("exec_argv")
		if len(argv) == 0 {
			argv = []string{"sh", "-c", a.ArgString("exec_command")}
		}
		if _, ok := m.lookup("Pod", ns, a.ArgString("pod")); !ok && !strings.Contains(name, "web") {
			// The simulator only knows the pods it seeded.
			if a.ArgString("pod") != "" && !strings.HasPrefix(a.ArgString("pod"), "web-") {
				return Result{Adapter: m.Name(), Status: "failed", Summary: "pod not found"}, fmt.Errorf("pod not found")
			}
		}
		return Result{
			Adapter: m.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("exec %s in %s/%s (simulator)", strings.Join(argv, " "), ns, name),
			Output:  simulatedExec(argv),
		}, nil

	default:
		manifest, err := manifestOf(a)
		if err != nil {
			return Result{Adapter: m.Name(), Status: "failed"}, err
		}
		if manifest == nil {
			manifest = map[string]any{}
		}
		m.put(kind, ns, name, manifest)
		return Result{Adapter: m.Name(), Status: "ok", Mutated: true,
			Summary: fmt.Sprintf("applied %s %s/%s (simulator)", kind, ns, name)}, nil
	}
}

func simulatedExec(argv []string) any {
	joined := strings.Join(argv, " ")
	switch {
	case strings.Contains(joined, "ls"):
		return "/etc/hosts  /etc/hostname  /etc/resolv.conf  /app  /tmp"
	case strings.Contains(joined, "passwd"):
		return "root:x:0:0:root:/root:/bin/sh\n(truncated by simulator)"
	case strings.Contains(joined, "env"):
		return "PATH=/usr/local/bin:/usr/bin\nHOSTNAME=web-7d9f\nDB_PASSWORD=[REDACTED]"
	default:
		return "(simulator) no output"
	}
}

// Rollback restores the captured object.
func (m *MockK8sAdapter) Rollback(ctx context.Context, a *action.Action, snap Snapshot) error {
	if snap.Strategy == "none" {
		return fmt.Errorf("no rollback available: %s", snap.Note)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch snap.Strategy {
	case "delete-on-rollback":
		delete(m.objects, key(a.ArgString("kind"), a.Resource.Namespace, a.Resource.Name))
		return nil
	case "restore-object":
		var obj map[string]any
		if err := json.Unmarshal(snap.Data, &obj); err != nil {
			return err
		}
		m.put(a.ArgString("kind"), a.Resource.Namespace, a.Resource.Name, obj)
		return nil
	default:
		return fmt.Errorf("unknown snapshot strategy %q", snap.Strategy)
	}
}

// Inventory is a debug helper used by the demo script.
func (m *MockK8sAdapter) Inventory() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
