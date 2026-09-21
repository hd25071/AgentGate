package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/mcp"
	"github.com/hd25071/AgentGate/internal/store"
)

// annotation reads are the MCP hints a host uses to decide whether to ask for
// confirmation. The gateway sets them honestly: redis_exec is not read-only
// even when the command happens to be a GET, because the gateway cannot know
// that at list time.
func annotate(title string, readOnly, destructive, idempotent bool) map[string]any {
	return map[string]any{
		"title":           title,
		"readOnlyHint":    readOnly,
		"destructiveHint": destructive,
		"idempotentHint":  idempotent,
		"openWorldHint":   true,
	}
}

func obj(props map[string]any, required ...string) map[string]any {
	req := []any{}
	for _, r := range required {
		req = append(req, r)
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             req,
		"additionalProperties": false,
	}
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// registerTools wires the MCP surface.
//
// Each action tool declares the target kind it normalizes into. Everything
// else -- auth, normalization, policy, approval, preview, execution, audit --
// is shared, which is what makes adding a fourth target system a matter of one
// normalizer and one .rego file.
func (g *Gateway) registerTools() {
	type actionTool struct {
		tool mcp.Tool
		kind action.Kind
	}

	tools := []actionTool{
		{
			kind: action.KindRedis,
			tool: mcp.Tool{
				Name:        "redis_exec",
				Description: "Run one Redis command against the managed instance. The command is normalized into a structured action and checked against policy before it is sent. Administrative, code-executing and keyspace-wide commands are refused.",
				InputSchema: obj(map[string]any{
					"command": strProp("A single Redis command, for example 'GET session:42' or 'SET feature:flag on'. Exactly one command; multi-command payloads are refused."),
				}, "command"),
				Annotations: annotate("Redis command", false, true, false),
			},
		},
		{
			kind: action.KindK8s,
			tool: mcp.Tool{
				Name:        "k8s_get",
				Description: "Read one Kubernetes object. Reading Secrets is treated as a credential-access event and requires approval.",
				InputSchema: obj(map[string]any{
					"kind":      strProp("Resource kind, e.g. Pod, Deployment, PersistentVolumeClaim."),
					"name":      strProp("Object name."),
					"namespace": strProp("Namespace. Ignored for cluster-scoped kinds."),
				}, "kind", "name"),
				Annotations: annotate("Read a Kubernetes object", true, false, true),
			},
		},
		{
			kind: action.KindK8s,
			tool: mcp.Tool{
				Name:        "k8s_apply",
				Description: "Apply a Kubernetes manifest with server-side apply. Always runs a dry run first; dry-run failures abort before anything is written.",
				InputSchema: obj(map[string]any{
					"kind":      strProp("Resource kind."),
					"name":      strProp("Object name."),
					"namespace": strProp("Namespace."),
					"manifest":  map[string]any{"type": "object", "description": "The object to apply, as JSON."},
				}, "kind", "name", "namespace", "manifest"),
				Annotations: annotate("Apply a manifest", false, true, true),
			},
		},
		{
			kind: action.KindK8s,
			tool: mcp.Tool{
				Name:        "k8s_delete",
				Description: "Delete one Kubernetes object. Deleting namespaces, nodes, persistent volumes, CRDs and stateful workloads is refused outright.",
				InputSchema: obj(map[string]any{
					"kind":      strProp("Resource kind."),
					"name":      strProp("Object name."),
					"namespace": strProp("Namespace."),
				}, "kind", "name", "namespace"),
				Annotations: annotate("Delete a Kubernetes object", false, true, false),
			},
		},
		{
			kind: action.KindK8s,
			tool: mcp.Tool{
				Name:        "k8s_scale",
				Description: "Change the replica count of a workload. Scaling a production workload to zero is refused.",
				InputSchema: obj(map[string]any{
					"kind":      strProp("Workload kind, e.g. Deployment or StatefulSet."),
					"name":      strProp("Workload name."),
					"namespace": strProp("Namespace."),
					"replicas":  intProp("Target replica count."),
				}, "kind", "name", "namespace", "replicas"),
				Annotations: annotate("Scale a workload", false, false, true),
			},
		},
		{
			kind: action.KindK8s,
			tool: mcp.Tool{
				Name:        "k8s_exec",
				Description: "Run a command inside a pod. Needs approval, and is refused outright in control-plane namespaces. Against a live cluster the adapter does not implement interactive exec; use a debug Job.",
				InputSchema: obj(map[string]any{
					"namespace": strProp("Namespace."),
					"pod":       strProp("Pod name."),
					"container": strProp("Container name."),
					"command":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "argv of the command."},
				}, "namespace", "pod", "command"),
				Annotations: annotate("Exec into a pod", false, true, false),
			},
		},
		{
			kind: action.KindVRP,
			tool: mcp.Tool{
				Name:        "net_config",
				Description: "Apply a Huawei VRP configuration block to a network device. Requires approval and a NetGuard reachability preview. The backing adapter is a simulator in this build; results say so.",
				InputSchema: obj(map[string]any{
					"config": strProp("The VRP configuration block."),
				}, "config"),
				Annotations: annotate("Apply a device configuration", false, true, false),
			},
		},
	}

	for _, at := range tools {
		at := at
		g.mcp.Add(at.tool, func(ctx context.Context, args map[string]any) (mcp.CallToolResult, error) {
			return g.Call(ctx, at.tool.Name, at.kind, args), nil
		})
	}

	// Control tools: these do not touch a target system, so they skip the
	// normalize/policy/execute path but still authenticate.
	g.mcp.Add(mcp.Tool{
		Name:        "agentgate_explain",
		Description: "Ask the gateway what it would decide for a tool call, without executing anything. Returns the normalized action, the decision, the reasons and the action hash.",
		InputSchema: obj(map[string]any{
			"tool":      strProp("The action tool to evaluate, e.g. k8s_delete."),
			"arguments": map[string]any{"type": "object", "description": "The arguments you would pass to that tool."},
		}, "tool", "arguments"),
		Annotations: annotate("Explain a policy decision", true, false, true),
	}, func(ctx context.Context, args map[string]any) (mcp.CallToolResult, error) {
		tool := asString(args["tool"])
		kind, ok := toolKind(tool)
		if !ok {
			return mcp.ErrorResult(fmt.Sprintf("%q is not an action tool", tool), nil), nil
		}
		return g.Explain(ctx, tool, kind, asMap(args["arguments"])), nil
	})

	g.mcp.Add(mcp.Tool{
		Name:        "agentgate_approval_status",
		Description: "Check the state of a pending approval without waiting.",
		InputSchema: obj(map[string]any{"approval_id": strProp("The approval id returned by a pending call.")}, "approval_id"),
		Annotations: annotate("Check an approval", true, false, true),
	}, func(ctx context.Context, args map[string]any) (mcp.CallToolResult, error) {
		ap, err := g.approval.Get(ctx, asString(args["approval_id"]))
		if err != nil {
			return mcp.ErrorResult(err.Error(), map[string]any{"status": "not_found"}), nil
		}
		return g.approvalResult(ap), nil
	})

	g.mcp.Add(mcp.Tool{
		Name:        "agentgate_approval_wait",
		Description: "Wait for a pending approval to be decided, then report the outcome. Returns as soon as the approval leaves the pending state or the timeout expires.",
		InputSchema: obj(map[string]any{
			"approval_id":     strProp("The approval id."),
			"timeout_seconds": intProp("How long to wait, at most 300 seconds."),
		}, "approval_id"),
		Annotations: annotate("Wait for an approval", true, false, true),
	}, func(ctx context.Context, args map[string]any) (mcp.CallToolResult, error) {
		timeout := time.Duration(asInt(args["timeout_seconds"])) * time.Second
		if timeout <= 0 || timeout > 5*time.Minute {
			timeout = 2 * time.Minute
		}
		ap, err := g.approval.Wait(ctx, asString(args["approval_id"]), timeout)
		if err != nil && ap == nil {
			return mcp.ErrorResult(err.Error(), map[string]any{"status": "not_found"}), nil
		}
		return g.approvalResult(ap), nil
	})
}

func (g *Gateway) approvalResult(ap *store.Approval) mcp.CallToolResult {
	structured := map[string]any{
		"status":             ap.Status,
		"approval_id":        ap.ID,
		"action_hash":        ap.ActionHash,
		"risk":               ap.Risk,
		"required_approvals": ap.Required,
		"votes":              ap.Approvals,
		"decision_note":      ap.DecisionNote,
		"summary":            ap.Summary,
	}
	if ap.ResultJSON != "" {
		structured["result"] = rawJSON(ap.ResultJSON)
	}
	text := fmt.Sprintf("approval %s is %s\n%s\naction_hash=%s", ap.ID, ap.Status, ap.Summary, ap.ActionHash)
	if ap.Status == store.StatusPending {
		text += fmt.Sprintf("\n%d of %d required approvals collected", countVotes(ap), ap.Required)
	}
	if ap.RollbackHint() != "" {
		text += "\nrollback: " + ap.RollbackHint()
	}
	return mcp.TextResult(text, structured)
}

func countVotes(ap *store.Approval) int {
	n := 0
	for _, v := range ap.Approvals {
		if v.Approve {
			n++
		}
	}
	return n
}

// toolKind maps an action tool name to its target kind.
func toolKind(tool string) (action.Kind, bool) {
	switch tool {
	case "redis_exec":
		return action.KindRedis, true
	case "k8s_get", "k8s_apply", "k8s_delete", "k8s_scale", "k8s_exec":
		return action.KindK8s, true
	case "net_config":
		return action.KindVRP, true
	default:
		return "", false
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case int64:
		return int(t)
	default:
		return 0
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
