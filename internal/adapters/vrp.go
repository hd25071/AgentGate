package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
)

// VRPConfig configures the network-device adapter.
type VRPConfig struct {
	Name string
	Env  string
	// Mode is "simulator" (default) or "ssh"/"netconf" once a real transport is
	// wired up. Only "simulator" is implemented; the adapter reports the mode it
	// is in on every result so nothing can be mistaken for a live change.
	Mode string

	Host     string
	Port     int
	Username string
	// Password is deliberately not read from agent-reachable config; it comes
	// from the gateway environment.
	Password string
	Timeout  time.Duration
}

// VRPAdapter applies VRP configuration blocks.
//
// Stage-3 surface. The normalizer and the policy rules are real; the transport
// is a simulator, and every result it produces says so. NetGuard impact
// analysis is invoked through the preview step (see internal/preview).
type VRPAdapter struct {
	cfg VRPConfig

	mu     sync.Mutex
	config []string // committed running-config lines
}

// NewVRPAdapter builds the adapter.
func NewVRPAdapter(cfg VRPConfig) *VRPAdapter {
	if cfg.Name == "" {
		cfg.Name = "vrp-edge-1"
	}
	if cfg.Mode == "" {
		cfg.Mode = "simulator"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	a := &VRPAdapter{cfg: cfg}
	a.config = []string{
		"sysname edge-1",
		"interface GigabitEthernet0/0/1",
		" description uplink",
		" undo shutdown",
		"acl number 3000",
		" rule 5 permit ip source 10.0.0.0 0.0.0.255 destination any",
		"quit",
	}
	return a
}

func (v *VRPAdapter) Kind() action.Kind { return action.KindVRP }
func (v *VRPAdapter) Name() string      { return v.cfg.Name }

// Health reports whether a real transport is configured.
func (v *VRPAdapter) Health(ctx context.Context) error {
	if v.cfg.Mode != "simulator" {
		return fmt.Errorf("VRP transport %q is not implemented; the gateway is refusing to pretend", v.cfg.Mode)
	}
	return nil
}

// Snapshot records the lines the change will touch.
func (v *VRPAdapter) Snapshot(ctx context.Context, a *action.Action) (Snapshot, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cfg := a.ArgString("config")
	snap := Snapshot{
		Adapter:  v.Name(),
		Strategy: "line-replay",
		TakenAt:  time.Now().UnixMilli(),
		Data:     []byte(fmt.Sprintf(`{"mode":%q,"before":%q,"lines":%d}`, v.cfg.Mode, strings.Join(v.config, "\n"), len(v.config))),
		Note:     "line-replay rollback restores the previous running-config; it cannot undo state that has already been programmed into forwarding hardware",
	}
	_ = cfg
	return snap, nil
}

// Preview asks NetGuard for an impact estimate.
//
// The adapter itself does not call NetGuard -- it reports what the change does
// locally, and internal/preview adds the reachability analysis. Splitting them
// keeps the adapter testable without a network.
func (v *VRPAdapter) Preview(ctx context.Context, a *action.Action) (PreviewResult, error) {
	out := PreviewResult{Adapter: v.Name(), Supported: true, Mode: v.cfg.Mode}
	out.Impact = fmt.Sprintf("would apply %d configuration lines to %s", a.ArgInt("line_count"), v.cfg.Name)
	if a.ArgBool("acl_deny_all") {
		out.Findings = append(out.Findings, "an ACL rule denies a wildcard source/destination pair: management access may be cut off")
	}
	if a.ArgInt("shutdown_count") > 0 {
		out.Findings = append(out.Findings, fmt.Sprintf("%d interface(s) would be shut down", a.ArgInt("shutdown_count")))
	}
	if a.ArgInt("route_policy_count") > 0 {
		out.Findings = append(out.Findings, "route-policy changes redirect traffic beyond this device; NetGuard impact analysis is required")
	}
	out.Findings = append(out.Findings, "mode="+v.cfg.Mode+": no packets are affected by this preview")
	return out, nil
}

// Execute commits the block to the simulator.
func (v *VRPAdapter) Execute(ctx context.Context, a *action.Action) (Result, error) {
	if v.cfg.Mode != "simulator" {
		return Result{Adapter: v.Name(), Status: "failed"},
			fmt.Errorf("%w: VRP transport %q", ErrNotSupported, v.cfg.Mode)
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	block := a.ArgString("config")
	lines := strings.Split(block, "\n")
	v.config = append(v.config, lines...)
	return Result{
		Adapter: v.Name(),
		Status:  "ok",
		Mutated: true,
		Summary: fmt.Sprintf("applied %d lines to %s [%s]", len(lines), v.cfg.Name, v.cfg.Mode),
		Output:  fmt.Sprintf("simulator: running-config is now %d lines", len(v.config)),
	}, nil
}

// Rollback restores the config lines captured before the change.
func (v *VRPAdapter) Rollback(ctx context.Context, a *action.Action, snap Snapshot) error {
	if snap.Strategy == "none" {
		return fmt.Errorf("no rollback available: %s", snap.Note)
	}
	var data struct {
		Before string `json:"before"`
	}
	if err := json.Unmarshal(snap.Data, &data); err != nil {
		return fmt.Errorf("rollback: snapshot did not parse: %w", err)
	}
	if data.Before == "" {
		return fmt.Errorf("rollback: snapshot carried no previous configuration")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config = strings.Split(data.Before, "\n")
	return nil
}

// RunningConfig exposes the simulator's state for the demo script.
func (v *VRPAdapter) RunningConfig() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return strings.Join(v.config, "\n")
}
