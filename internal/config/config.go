// Package config loads the gateway's own configuration.
//
// One rule shapes the whole file: every value an Agent can influence has a
// gateway-side counterpart that the Agent cannot. Target endpoints, the
// environment label ("prod" vs "staging") and, above all, the credentials live
// here and are read from the process environment. The Agent names a target
// symbolically; the gateway decides what that name resolves to.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/adapters"
)

// Config is the resolved gateway configuration.
type Config struct {
	HTTPAddr    string
	AdminAddr   string
	AdminToken  string
	TokenSecret string
	TokenTTL    time.Duration
	ExecTimeout time.Duration

	StoreDriver string
	StoreDSN    string

	PolicyDirs []string

	ApprovalTTL          time.Duration
	ApprovalWebhookURL   string
	ApprovalWebhookShape string

	RollbackOnFailure bool

	NetGuardURL string

	K8s   adapters.K8sConfig
	Redis adapters.RedisConfig
	VRP   adapters.VRPConfig

	OTelEndpoint string
	OTelInsecure bool
	OTelSample   float64

	// Targets maps a target kind to the logical target the policy engine sees.
	Targets map[action.Kind]action.Target
}

// Load reads the environment and validates it.
func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:    env("AG_HTTP_ADDR", ":8080"),
		AdminAddr:   env("AG_ADMIN_ADDR", ""),
		AdminToken:  env("AG_ADMIN_TOKEN", ""),
		TokenSecret: env("AG_TOKEN_SECRET", ""),
		TokenTTL:    envDuration("AG_TOKEN_TTL", time.Hour),
		ExecTimeout: envDuration("AG_EXEC_TIMEOUT", 60*time.Second),

		StoreDriver: env("AG_STORE_DRIVER", "sqlite"),
		StoreDSN:    env("AG_STORE_DSN", "file:/data/agentgate.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"),

		PolicyDirs: splitList(env("AG_POLICY_DIR", "")),

		ApprovalTTL:          envDuration("AG_APPROVAL_TTL", 30*time.Minute),
		ApprovalWebhookURL:   env("AG_APPROVAL_WEBHOOK_URL", ""),
		ApprovalWebhookShape: env("AG_APPROVAL_WEBHOOK_SHAPE", "generic"),

		RollbackOnFailure: envBool("AG_ROLLBACK_ON_FAILURE", true),

		NetGuardURL: env("AG_NETGUARD_URL", ""),

		K8s: adapters.K8sConfig{
			Name:       env("AG_K8S_NAME", "k8s-cluster"),
			Env:        env("AG_ENV", "staging"),
			Mode:       env("AG_K8S_MODE", "mock"),
			Server:     env("AG_K8S_SERVER", ""),
			Token:      env("AG_K8S_TOKEN", ""),
			Kubeconfig: env("AG_K8S_KUBECONFIG", ""),
			Context:    env("AG_K8S_CONTEXT", ""),
			Insecure:   envBool("AG_K8S_INSECURE", false),
			Timeout:    envDuration("AG_K8S_TIMEOUT", 15*time.Second),
		},
		Redis: adapters.RedisConfig{
			Name:     env("AG_REDIS_NAME", "redis-primary"),
			Addr:     env("AG_REDIS_ADDR", "redis:6379"),
			Username: env("AG_REDIS_USERNAME", ""),
			Password: env("AG_REDIS_PASSWORD", ""),
			DB:       envInt("AG_REDIS_DB", 0),
			Env:      env("AG_ENV", "staging"),
			Timeout:  envDuration("AG_REDIS_TIMEOUT", 5*time.Second),
		},
		VRP: adapters.VRPConfig{
			Name:     env("AG_VRP_NAME", "vrp-edge-1"),
			Env:      env("AG_ENV", "staging"),
			Mode:     env("AG_VRP_MODE", "simulator"),
			Host:     env("AG_VRP_HOST", ""),
			Port:     envInt("AG_VRP_PORT", 22),
			Username: env("AG_VRP_USERNAME", ""),
			Password: env("AG_VRP_PASSWORD", ""),
			Timeout:  envDuration("AG_VRP_TIMEOUT", 20*time.Second),
		},

		OTelEndpoint: env("AG_OTEL_ENDPOINT", ""),
		OTelInsecure: envBool("AG_OTEL_INSECURE", true),
		OTelSample:   envFloat("AG_OTEL_SAMPLE", 1),
	}

	if c.K8s.Insecure && c.K8s.Server != "" {
		// Allowed, but the operator should know they asked for it.
		fmt.Fprintln(os.Stderr, "agentgate: warning: AG_K8S_INSECURE=true disables API server certificate verification")
	}

	c.Targets = map[action.Kind]action.Target{
		action.KindRedis: {Kind: action.KindRedis, Name: c.Redis.Name, Endpoint: "gw:redis", Env: c.Redis.Env},
		action.KindK8s:   {Kind: action.KindK8s, Name: c.K8s.Name, Endpoint: "gw:k8s", Env: c.K8s.Env},
		action.KindVRP:   {Kind: action.KindVRP, Name: c.VRP.Name, Endpoint: "gw:vrp", Env: c.VRP.Env},
	}
	return c, nil
}

// Validate fails fast on configurations that would silently weaken the gateway.
func (c *Config) Validate() error {
	if c.TokenSecret == "" {
		return fmt.Errorf("AG_TOKEN_SECRET is required: the gateway will not issue unsigned tokens")
	}
	if len(c.TokenSecret) < 16 {
		return fmt.Errorf("AG_TOKEN_SECRET must be at least 16 bytes, got %d", len(c.TokenSecret))
	}
	if c.AdminToken == "" {
		return fmt.Errorf("AG_ADMIN_TOKEN is required: the approval API must not be open")
	}
	if c.AdminToken == c.TokenSecret {
		return fmt.Errorf("AG_ADMIN_TOKEN must differ from AG_TOKEN_SECRET")
	}
	if len(c.AdminToken) < 16 {
		return fmt.Errorf("AG_ADMIN_TOKEN must be at least 16 bytes, got %d", len(c.AdminToken))
	}
	switch c.StoreDriver {
	case "sqlite", "postgres", "":
	default:
		return fmt.Errorf("AG_STORE_DRIVER must be sqlite or postgres, got %q", c.StoreDriver)
	}
	if c.K8s.Mode != "mock" && c.K8s.Mode != "cluster" {
		return fmt.Errorf("AG_K8S_MODE must be mock or cluster, got %q", c.K8s.Mode)
	}
	if c.VRP.Mode != "simulator" && c.VRP.Mode != "ssh" && c.VRP.Mode != "netconf" {
		return fmt.Errorf("AG_VRP_MODE must be simulator, ssh or netconf; got %q", c.VRP.Mode)
	}
	return nil
}

// Env reports the declared environment, used in the startup banner.
func (c *Config) Env() string { return c.Redis.Env }

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return def
	}
	return f
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return d
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
