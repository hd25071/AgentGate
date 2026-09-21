package preview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnalyzeRequest is what the gateway asks NetGuard to evaluate.
type AnalyzeRequest struct {
	Device      string `json:"device"`
	ConfigBlock string `json:"config_block"`
	LineCount   int    `json:"line_count"`
}

// Report is NetGuard's answer: which reachability pairs a change would break.
type Report struct {
	Engine           string   `json:"engine"`
	RiskLevel        string   `json:"risk_level"` // none | low | medium | high
	AffectedPrefixes []string `json:"affected_prefixes"`
	AffectedPeers    []string `json:"affected_peers"`
	Notes            []string `json:"notes"`
	// Simulated marks an answer produced by the local heuristic rather than by
	// a real NetGuard instance. It is surfaced in the approval card so nobody
	// approves a change believing a real reachability model ran.
	Simulated bool `json:"simulated"`
}

// Summary renders a one-line description for the approval card.
func (r *Report) Summary() string {
	if r == nil {
		return ""
	}
	tag := ""
	if r.Simulated {
		tag = " [simulated]"
	}
	return fmt.Sprintf("NetGuard%s: risk=%s, %d prefix(es), %d peer(s)",
		tag, r.RiskLevel, len(r.AffectedPrefixes), len(r.AffectedPeers))
}

// NetGuardClient is the reachability analysis interface.
type NetGuardClient interface {
	Analyze(ctx context.Context, req AnalyzeRequest) (*Report, error)
	Name() string
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

// HTTPNetGuard calls a real NetGuard deployment.
type HTTPNetGuard struct {
	URL    string
	Client *http.Client
}

// NewHTTPNetGuard builds the client.
func NewHTTPNetGuard(url string) *HTTPNetGuard {
	return &HTTPNetGuard{URL: url, Client: &http.Client{Timeout: 15 * time.Second}}
}

func (h *HTTPNetGuard) Name() string { return "netguard-http" }

// Analyze posts the change and decodes the report.
func (h *HTTPNetGuard) Analyze(ctx context.Context, req AnalyzeRequest) (*Report, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := h.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("netguard returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("netguard reply did not parse: %w", err)
	}
	rep.Engine = h.Name()
	return &rep, nil
}

// ---------------------------------------------------------------------------
// Local heuristic
// ---------------------------------------------------------------------------

// LocalNetGuard applies a small, explicit rule set to the config block.
//
// It is not a reachability model and does not claim to be. What it does is turn
// "we have no NetGuard yet" into a structured, clearly-labelled finding rather
// than an empty field that reads like approval.
type LocalNetGuard struct{}

// NewLocalNetGuard builds the fallback.
func NewLocalNetGuard() *LocalNetGuard { return &LocalNetGuard{} }

func (LocalNetGuard) Name() string { return "netguard-local-heuristic" }

// Analyze inspects the block for the constructs that actually break networks.
func (LocalNetGuard) Analyze(ctx context.Context, req AnalyzeRequest) (*Report, error) {
	rep := &Report{Engine: "netguard-local-heuristic", Simulated: true, RiskLevel: "low"}
	cfg := strings.ToLower(req.ConfigBlock)

	switch {
	case strings.Contains(cfg, "reset saved-configuration"):
		rep.RiskLevel = "high"
		rep.Notes = append(rep.Notes, "device configuration would be erased")
	case strings.Contains(cfg, "shutdown"):
		rep.RiskLevel = "high"
		rep.Notes = append(rep.Notes, "an interface would be administratively down")
	case strings.Contains(cfg, "route-policy") || strings.Contains(cfg, "traffic-policy"):
		rep.RiskLevel = "medium"
		rep.Notes = append(rep.Notes, "policy-based routing changes can shift traffic paths beyond this device")
	case strings.Contains(cfg, "acl number") || strings.Contains(cfg, "acl name"):
		rep.RiskLevel = "medium"
		rep.Notes = append(rep.Notes, "ACL changes affect the traffic they match")
	}

	if strings.Contains(cfg, "source any destination any") && strings.Contains(cfg, "deny") {
		rep.RiskLevel = "high"
		rep.Notes = append(rep.Notes, "a deny-any rule would be installed; management reachability cannot be guaranteed")
	}
	if strings.Contains(cfg, "bgp") && strings.Contains(cfg, "peer") {
		rep.AffectedPeers = append(rep.AffectedPeers, "bgp peers referenced by the block")
		rep.RiskLevel = bump(rep.RiskLevel)
	}

	if rep.RiskLevel != "low" {
		rep.AffectedPrefixes = append(rep.AffectedPrefixes, "prefixes matched by the changed policy (local heuristic cannot enumerate them)")
	}
	rep.Notes = append(rep.Notes, "local heuristic: run NetGuard for a real reachability matrix")
	return rep, nil
}

func bump(level string) string {
	switch level {
	case "none":
		return "low"
	case "low":
		return "medium"
	case "medium":
		return "high"
	default:
		return "high"
	}
}
