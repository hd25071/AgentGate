package action

import (
	"fmt"
	"regexp"
	"strings"
)

// VRPNormalizer parses Huawei VRP configuration blocks.
//
// Scope note: per the staged plan, the VRP path ships with a simulator-backed
// adapter and is labelled as such everywhere it surfaces. The normalizer is
// real -- the parser below is the same one a device would face -- but the
// executor talks to a simulator, not a router.
type VRPNormalizer struct{}

func (VRPNormalizer) Tool() string { return "net_config" }

var (
	reACLRule      = regexp.MustCompile(`(?i)^\s*rule\s+(\d+)\s+(permit|deny)\s+(.*)$`)
	reACLNumber    = regexp.MustCompile(`(?i)^\s*acl\s+(number\s+)?(\d+|name\s+\S+)\s*$`)
	reInterface    = regexp.MustCompile(`(?i)^\s*interface\s+(\S+)\s*$`)
	reBGP          = regexp.MustCompile(`(?i)^\s*bgp\s+(\d+)\s*$`)
	rePeer         = regexp.MustCompile(`(?i)^\s*peer\s+(\S+)\s*`)
	reRoutePolicy  = regexp.MustCompile(`(?i)^\s*route-policy\s+(\S+)\s*`)
	reTrafficPol   = regexp.MustCompile(`(?i)^\s*traffic-policy\s+(\S+)\s*`)
	reShutdown     = regexp.MustCompile(`(?i)^\s*shutdown\s*$`)
	reUndo         = regexp.MustCompile(`(?i)^\s*undo\s+(.+)$`)
	reResetSaved   = regexp.MustCompile(`(?i)^\s*reset\s+saved-configuration\s*$`)
	reUserPassword = regexp.MustCompile(`(?i)^\s*local-user\s+(\S+)\s*$`)
)

func (VRPNormalizer) Normalize(args map[string]any, tgt Target) (*Action, error) {
	cfg := str(args["config"])
	if strings.TrimSpace(cfg) == "" {
		cfg = str(args["block"])
	}
	if strings.TrimSpace(cfg) == "" {
		return nil, fmt.Errorf("%w: net_config requires a non-empty config block", ErrInvalidArgs)
	}

	lines := splitLines(cfg)
	blocks := map[string]int{}
	var aclRules, deniedAll, permitAny, shutdown, undoLines, peers, policies []string
	lineCount := 0

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		lineCount++

		if m := reInterface.FindStringSubmatch(line); m != nil {
			blocks["interface"]++
		}
		if m := reACLNumber.FindStringSubmatch(line); m != nil {
			blocks["acl"]++
		}
		if reBGP.MatchString(line) {
			blocks["bgp"]++
		}
		if m := reRoutePolicy.FindStringSubmatch(line); m != nil {
			blocks["route-policy"]++
			policies = append(policies, m[1])
		}
		if m := reTrafficPol.FindStringSubmatch(line); m != nil {
			blocks["traffic-policy"]++
			policies = append(policies, m[1])
		}
		if m := rePeer.FindStringSubmatch(line); m != nil {
			peers = append(peers, m[1])
		}
		if m := reACLRule.FindStringSubmatch(line); m != nil {
			aclRules = append(aclRules, line)
			src := strings.ToLower(m[3])
			if m[2] == "deny" || m[2] == "DENY" {
				if strings.Contains(src, "source any") || strings.Contains(src, "destination any") {
					deniedAll = append(deniedAll, line)
				}
			}
			if strings.Contains(src, "source any destination any") {
				permitAny = append(permitAny, line)
			}
		}
		if reShutdown.MatchString(line) {
			shutdown = append(shutdown, line)
		}
		if m := reUndo.FindStringSubmatch(line); m != nil {
			undoLines = append(undoLines, strings.TrimSpace(m[1]))
		}
		if reResetSaved.MatchString(line) {
			blocks["reset-saved-configuration"]++
		}
		if reUserPassword.MatchString(line) {
			blocks["local-user"]++
		}
	}

	if lineCount == 0 {
		return nil, fmt.Errorf("%w: config block contained no directives", ErrInvalidArgs)
	}

	broadDeny := len(deniedAll) > 0
	out := map[string]any{
		"config":              cfg,
		"line_count":          lineCount,
		"block_types":         sortedKeys(blocks),
		"block_count":         len(blocks),
		"acl_rule_count":      len(aclRules),
		"acl_deny_all":        broadDeny,
		"acl_permit_any":      len(permitAny) > 0,
		"shutdown_count":      len(shutdown),
		"has_undo":            len(undoLines) > 0,
		"bgp_peer_count":      len(peers),
		"route_policy_count":  len(policies),
		"resets_saved_config": blocks["reset-saved-configuration"] > 0,
		"touches_local_users": blocks["local-user"] > 0,
		"multi_block":         len(blocks) > 1,
		"set:policies":        policies,
		"set:bgp_peers":       peers,
	}
	if len(shutdown) > 0 {
		out["set:shutdown_lines"] = shutdown
	}

	verb := VerbConfig
	if broadDeny || len(shutdown) > 0 || blocks["reset-saved-configuration"] > 0 {
		verb = VerbDelete
	}

	scope := ScopeDevice
	if len(policies) > 0 || blocks["bgp"] > 0 {
		scope = ScopeSite
	}

	a := &Action{
		Tool:   "net_config",
		Target: tgt,
		Verb:   verb,
		Resource: Resource{
			Type:  "device-config",
			Name:  firstOr(sortedKeys(blocks), "config"),
			Count: lineCount,
		},
		Args: out,
		BlastRadius: BlastRadius{
			Scope:        scope,
			Affected:     -1,
			Irreversible: blocks["reset-saved-configuration"] > 0,
			Production:   strings.EqualFold(tgt.Env, "prod"),
		},
		Raw: cfg,
	}
	if err := a.Seal(); err != nil {
		return nil, err
	}
	return a, nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion sort keeps this dependency-free and the slices are tiny
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func firstOr(s []string, def string) string {
	if len(s) == 0 {
		return def
	}
	return s[0]
}
