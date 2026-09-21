// Command agentgate is the gateway itself.
//
// It has two modes. `serve` runs the HTTP surface an MCP client connects to;
// `mcp-stdio` runs the same pipeline over stdin/stdout for hosts that launch
// servers as a subprocess. Both modes share one pipeline: there is no path that
// reaches an adapter without going through policy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hd25071/AgentGate/internal/adapters"
	"github.com/hd25071/AgentGate/internal/audit"
	"github.com/hd25071/AgentGate/internal/auth"
	"github.com/hd25071/AgentGate/internal/config"
	"github.com/hd25071/AgentGate/internal/gateway"
	"github.com/hd25071/AgentGate/internal/mcp"
	"github.com/hd25071/AgentGate/internal/policy"
	"github.com/hd25071/AgentGate/internal/preview"
	"github.com/hd25071/AgentGate/internal/store"
	"github.com/hd25071/AgentGate/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agentgate:", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]

	var (
		policyDirs  multiFlag
		showVersion bool
		logFormat   string
	)
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	fs := newFlagSet(command)
	fs.Var(&policyDirs, "policy-dir", "directory of .rego files, replacing the embedded bundle (repeatable)")
	fs.BoolVar(&showVersion, "version", false, "print the build version and exit")
	fs.StringVar(&logFormat, "log-format", envOr("AG_LOG_FORMAT", "text"), "text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Println("agentgate " + version.String())
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if len(policyDirs) > 0 {
		cfg.PolicyDirs = policyDirs
	}

	logger := newLogger(logFormat)

	if command == "mcp-stdio" {
		return runStdio(cfg, logger)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%w\n\nGenerate secrets with:\n  agentgate-cli token secret", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := audit.SetupTracing(ctx, audit.TracingConfig{
		Endpoint:       cfg.OTelEndpoint,
		Insecure:       cfg.OTelInsecure,
		SampleRate:     cfg.OTelSample,
		ServiceName:    "agentgate",
		ServiceVersion: version.Version,
	})
	if err != nil {
		return err
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	gw, closer, err := build(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closer()

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           gw.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Approval waits are long-lived by design; the write timeout has to
		// accommodate the longest poll the MCP surface allows.
		WriteTimeout: 6 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("agentgate listening",
			"addr", cfg.HTTPAddr,
			"env", cfg.Env(),
			"policy", gw.Policy().Version(),
			"policy_source", gw.Policy().Source(),
			"k8s_mode", cfg.K8s.Mode,
			"vrp_mode", cfg.VRP.Mode,
			"version", version.String(),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Expired approvals must not sit in the queue looking actionable.
	go sweepLoop(ctx, gw, logger)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// build assembles the gateway from configuration.
func build(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*gateway.Gateway, func(), error) {
	st, err := store.Open(ctx, cfg.StoreDriver, cfg.StoreDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	closer := func() { _ = st.Close() }

	signer, err := auth.NewSigner([]byte(cfg.TokenSecret), "agentgate")
	if err != nil {
		closer()
		return nil, nil, err
	}

	engine, err := policy.NewRegoEngine(ctx, cfg.PolicyDirs)
	if err != nil {
		closer()
		return nil, nil, err
	}

	adaptersReg, err := buildAdapters(cfg)
	if err != nil {
		closer()
		return nil, nil, err
	}

	var ng preview.NetGuardClient
	if cfg.NetGuardURL != "" {
		ng = preview.NewHTTPNetGuard(cfg.NetGuardURL)
		logger.Info("netguard client configured", "url", cfg.NetGuardURL)
	} else if cfg.VRP.Mode != "" {
		ng = preview.NewLocalNetGuard()
		logger.Warn("no AG_NETGUARD_URL set: network changes get the local heuristic, clearly labelled as simulated")
	}

	gw, err := gateway.New(gateway.Deps{
		Config:   cfg,
		Logger:   logger,
		Store:    st,
		Signer:   signer,
		Policy:   engine,
		Adapters: adaptersReg,
		NetGuard: ng,
	})
	if err != nil {
		closer()
		return nil, nil, err
	}
	return gw, closer, nil
}

func buildAdapters(cfg *config.Config) (*adapters.Registry, error) {
	reg := adapters.NewRegistry()
	reg.Register(adapters.NewRedisAdapter(cfg.Redis))

	switch cfg.K8s.Mode {
	case "mock":
		reg.Register(adapters.NewMockK8sAdapter(cfg.K8s))
	case "cluster":
		a, err := adapters.NewK8sAdapter(cfg.K8s)
		if err != nil {
			return nil, err
		}
		reg.Register(a)
	default:
		return nil, fmt.Errorf("AG_K8S_MODE must be mock or cluster, got %q", cfg.K8s.Mode)
	}

	reg.Register(adapters.NewVRPAdapter(cfg.VRP))
	return reg, nil
}

// runStdio serves the MCP protocol over stdin/stdout.
func runStdio(cfg *config.Config, logger *slog.Logger) error {
	token := os.Getenv("AG_MCP_TOKEN")
	if token == "" {
		return fmt.Errorf("AG_MCP_TOKEN is required in mcp-stdio mode: there is no HTTP layer to authenticate against")
	}
	if cfg.TokenSecret == "" {
		return fmt.Errorf("AG_TOKEN_SECRET is required so the token can be verified")
	}
	ctx := context.Background()

	gw, closer, err := build(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closer()

	claims, err := gw.Signer().Verify(token)
	if err != nil {
		return fmt.Errorf("AG_MCP_TOKEN was rejected: %w", err)
	}
	ident := mcp.Identity{
		Subject: claims.Subject,
		Scopes:  claims.Scopes,
		Session: claims.Session,
		TokenID: claims.TokenID,
	}
	// stderr carries logs; stdout carries protocol frames only.
	logger.Info("agentgate mcp-stdio ready", "subject", claims.Subject, "scopes", claims.Scopes)
	return gw.MCPServer().ServeStdio(ctx, os.Stdin, os.Stdout, ident)
}

// sweepLoop expires overdue approvals and reports on them.
func sweepLoop(ctx context.Context, gw *gateway.Gateway, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := gw.Approvals().ExpireSweep(ctx); err != nil {
				logger.Warn("approval expiry sweep failed", "err", err)
			} else if n > 0 {
				logger.Info("expired stale approvals", "count", n)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Small utilities kept local so the binary has no CLI framework dependency
// ---------------------------------------------------------------------------

func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// newFlagSet builds a flag set whose usage text names the command it belongs
// to, so `agentgate serve -h` and `agentgate mcp-stdio -h` do not both print
// the same generic banner.
func newFlagSet(command string) *flag.FlagSet {
	fs := flag.NewFlagSet("agentgate "+command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: agentgate %s [flags]\n\n", command)
		fs.PrintDefaults()
	}
	return fs
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
