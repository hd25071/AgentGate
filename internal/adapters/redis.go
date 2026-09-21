package adapters

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
)

// RedisConfig configures the Redis adapter.
type RedisConfig struct {
	Name     string
	Addr     string
	Username string
	Password string
	DB       int
	Env      string
	Timeout  time.Duration
	// SnapshotMaxKeys bounds how much rollback material one action may carry.
	// A generous snapshot is worthless if capturing it stalls the instance.
	SnapshotMaxKeys int
}

// RedisAdapter executes Redis actions over RESP.
type RedisAdapter struct {
	cfg RedisConfig
}

// NewRedisAdapter builds the adapter.
func NewRedisAdapter(cfg RedisConfig) *RedisAdapter {
	if cfg.Name == "" {
		cfg.Name = "redis-primary"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.SnapshotMaxKeys <= 0 {
		cfg.SnapshotMaxKeys = 100
	}
	return &RedisAdapter{cfg: cfg}
}

func (r *RedisAdapter) Kind() action.Kind { return action.KindRedis }
func (r *RedisAdapter) Name() string      { return r.cfg.Name }

// refusedCommands is an independent second gate.
//
// Policy already denies these. Keeping the list here too is not redundancy for
// its own sake: the adapter is the last thing between a bug in the policy
// bundle and a production FLUSHALL, and the cost of the duplicate check is one
// map lookup.
var refusedCommands = map[string]bool{
	"FLUSHALL": true, "FLUSHDB": true, "SWAPDB": true, "SHUTDOWN": true,
	"DEBUG": true, "SLAVEOF": true, "REPLICAOF": true, "FAILOVER": true,
	"MODULE": true, "ACL": true, "MIGRATE": true, "RESTORE": true,
	"EVAL": true, "EVALSHA": true, "FCALL": true, "FCALL_RO": true,
	"MONITOR": true,
}

func (r *RedisAdapter) Health(ctx context.Context) error {
	c, err := r.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	reply, err := c.Do(ctx, "PING")
	if err != nil {
		return err
	}
	if strings.ToUpper(stringify(reply)) != "PONG" {
		return fmt.Errorf("unexpected PING reply: %s", stringify(reply))
	}
	return nil
}

func (r *RedisAdapter) dial(ctx context.Context) (*respClient, error) {
	return dialRESP(ctx, r.cfg.Addr, r.cfg.Username, r.cfg.Password, r.cfg.DB, r.cfg.Timeout)
}

func (r *RedisAdapter) argv(a *action.Action) ([]string, error) {
	argv := a.ArgStrings("argv")
	if len(argv) == 0 {
		return nil, fmt.Errorf("redis action carries no normalized argv")
	}
	if refusedCommands[strings.ToUpper(argv[0])] {
		return nil, fmt.Errorf("redis adapter refuses %s independently of policy: it is on the never-execute list", strings.ToUpper(argv[0]))
	}
	return argv, nil
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

type keySnapshot struct {
	Key     string `json:"key"`
	Existed bool   `json:"existed"`
	Type    string `json:"type,omitempty"`
	Dump    string `json:"dump,omitempty"` // base64 of the DUMP payload
	TTLms   int64  `json:"ttl_ms"`
}

type redisSnapshotData struct {
	Keys     []keySnapshot  `json:"keys,omitempty"`
	Config   map[string]any `json:"config,omitempty"`
	Strategy string         `json:"strategy"`
}

// Snapshot captures rollback material.
//
// Reads get nothing: there is nothing to undo. Writes and deletes get a DUMP of
// every named key, which is an exact binary restore. CONFIG changes get the
// previous value. Anything policy allows but this cannot snapshot is reported
// as best-effort with a note, never as "safe".
func (r *RedisAdapter) Snapshot(ctx context.Context, a *action.Action) (Snapshot, error) {
	snap := Snapshot{Adapter: r.Name(), TakenAt: time.Now().UnixMilli()}
	if a.Verb == action.VerbRead {
		snap.Strategy = "none"
		snap.Note = "read-only action: nothing to roll back"
		snap.Data = json.RawMessage(`{}`)
		return snap, nil
	}

	c, err := r.dial(ctx)
	if err != nil {
		return snap, err
	}
	defer func() { _ = c.Close() }()

	data := redisSnapshotData{}
	cmd := strings.ToUpper(a.ArgString("command_upper"))

	switch {
	case cmd == "CONFIG":
		param := a.ArgString("config_param")
		reply, err := c.Do(ctx, "CONFIG", "GET", param)
		if err != nil {
			return snap, fmt.Errorf("snapshot CONFIG GET %s: %w", param, err)
		}
		data.Config = map[string]any{"param": param, "previous": reply}
		data.Strategy = "config-restore"
		snap.Strategy = "config-restore"
		snap.Note = fmt.Sprintf("previous value of %s is recorded; rollback issues CONFIG SET back to it", param)

	default:
		keys := a.ArgStrings("keys")
		if len(keys) == 0 {
			snap.Strategy = "best-effort"
			snap.Note = "policy allowed this action but no key was named, so there is nothing to snapshot"
			snap.Data = json.RawMessage(`{}`)
			return snap, nil
		}
		if len(keys) > r.cfg.SnapshotMaxKeys {
			snap.Strategy = "best-effort"
			snap.Note = fmt.Sprintf("%d keys exceeds the %d key snapshot budget; rollback would be incomplete", len(keys), r.cfg.SnapshotMaxKeys)
			snap.Data = json.RawMessage(`{}`)
			return snap, nil
		}
		for _, k := range keys {
			ks := keySnapshot{Key: k}
			typ, err := c.Do(ctx, "TYPE", k)
			if err != nil {
				return snap, fmt.Errorf("snapshot TYPE %s: %w", k, err)
			}
			ks.Type = stringify(typ)
			if ks.Type != "none" {
				ks.Existed = true
				dump, err := c.Do(ctx, "DUMP", k)
				if err == nil {
					if s, ok := dump.(string); ok {
						ks.Dump = base64.StdEncoding.EncodeToString([]byte(s))
					}
				}
				ttl, err := c.Do(ctx, "PTTL", k)
				if err == nil {
					ks.TTLms, _ = ttl.(int64)
				}
			}
			data.Keys = append(data.Keys, ks)
		}
		data.Strategy = "dump-restore"
		snap.Strategy = "dump-restore"
		snap.Note = fmt.Sprintf("%d key(s) captured with DUMP; rollback restores or deletes exactly those keys", len(data.Keys))
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return snap, err
	}
	snap.Data = raw
	return snap, nil
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

// Preview answers "what would this touch" without writing anything.
func (r *RedisAdapter) Preview(ctx context.Context, a *action.Action) (PreviewResult, error) {
	out := PreviewResult{Adapter: r.Name(), Supported: true}
	if a.Verb == action.VerbRead {
		out.Impact = "read-only: no state changes"
		return out, nil
	}

	c, err := r.dial(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = c.Close() }()

	cmd := a.ArgString("command_upper")
	if cmd == "CONFIG" {
		param := a.ArgString("config_param")
		cur, err := c.Do(ctx, "CONFIG", "GET", param)
		if err != nil {
			return out, err
		}
		out.Impact = fmt.Sprintf("CONFIG %s will change %s", a.ArgString("subcommand_upper"), param)
		out.Findings = append(out.Findings, "current value: "+stringify(cur))
		out.Details = map[string]any{"current": cur}
		return out, nil
	}

	keys := a.ArgStrings("keys")
	if len(keys) == 0 {
		out.Impact = "no named key to inspect"
		return out, nil
	}
	for _, k := range keys {
		typ, err := c.Do(ctx, "TYPE", k)
		if err != nil {
			return out, err
		}
		t := stringify(typ)
		if t == "none" {
			out.Findings = append(out.Findings, fmt.Sprintf("%s: does not exist (this action creates it)", k))
			continue
		}
		size := redisSize(ctx, c, k, t)
		out.Findings = append(out.Findings, fmt.Sprintf("%s: %s with %s", k, t, size))
	}
	out.Impact = fmt.Sprintf("%s will affect %d existing key(s)", cmd, len(keys))
	return out, nil
}

func redisSize(ctx context.Context, c *respClient, key, typ string) string {
	var cmd string
	switch typ {
	case "string":
		cmd = "STRLEN"
	case "list":
		cmd = "LLEN"
	case "set":
		cmd = "SCARD"
	case "zset":
		cmd = "ZCARD"
	case "hash":
		cmd = "HLEN"
	default:
		return "unknown size"
	}
	reply, err := c.Do(ctx, cmd, key)
	if err != nil {
		return "unknown size"
	}
	return fmt.Sprintf("%s = %s", cmd, stringify(reply))
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

// Execute sends the normalized argv.
func (r *RedisAdapter) Execute(ctx context.Context, a *action.Action) (Result, error) {
	argv, err := r.argv(a)
	if err != nil {
		return Result{Adapter: r.Name(), Status: "failed"}, err
	}
	c, err := r.dial(ctx)
	if err != nil {
		return Result{Adapter: r.Name(), Status: "failed"}, err
	}
	defer func() { _ = c.Close() }()

	started := time.Now()
	reply, err := c.Do(ctx, argv...)
	if err != nil {
		return Result{Adapter: r.Name(), Status: "failed", Summary: "redis rejected the command: " + err.Error()},
			fmt.Errorf("redis %s: %w", strings.ToUpper(argv[0]), err)
	}
	res := Result{
		Adapter: r.Name(),
		Status:  "ok",
		Summary: fmt.Sprintf("%s completed in %s", strings.ToUpper(argv[0]), time.Since(started).Round(time.Millisecond)),
		Output:  Sanitize(stringify(reply)),
		Mutated: a.Verb != action.VerbRead,
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

// Rollback restores the snapshot.
func (r *RedisAdapter) Rollback(ctx context.Context, a *action.Action, snap Snapshot) error {
	if snap.Strategy == "none" || len(snap.Data) == 0 || string(snap.Data) == "{}" {
		return fmt.Errorf("no rollback material was captured (%s)", snap.Note)
	}
	c, err := r.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	var data redisSnapshotData
	if err := json.Unmarshal(snap.Data, &data); err != nil {
		return err
	}

	switch data.Strategy {
	case "config-restore":
		param, _ := data.Config["param"].(string)
		prev := data.Config["previous"]
		pairs, ok := prev.([]any)
		if !ok || len(pairs) < 2 {
			return fmt.Errorf("snapshot did not record a previous value for %s", param)
		}
		value := stringify(pairs[1])
		if _, err := c.Do(ctx, "CONFIG", "SET", param, value); err != nil {
			return fmt.Errorf("rollback CONFIG SET %s: %w", param, err)
		}
		return nil
	case "dump-restore":
		for _, ks := range data.Keys {
			if !ks.Existed {
				if _, err := c.Do(ctx, "DEL", ks.Key); err != nil {
					return fmt.Errorf("rollback DEL %s: %w", ks.Key, err)
				}
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(ks.Dump)
			if err != nil {
				return fmt.Errorf("rollback: corrupt dump for %s: %w", ks.Key, err)
			}
			ttlArg := "0"
			if ks.TTLms > 0 {
				ttlArg = fmt.Sprint(ks.TTLms)
			}
			if _, err := c.Do(ctx, "RESTORE", ks.Key, ttlArg, string(raw), "REPLACE"); err != nil {
				// RESTORE is on the adapter's never-execute list for *agent*
				// commands. Rollback is a different trust path: it runs from a
				// snapshot the gateway took, with no agent input in the value.
				return fmt.Errorf("rollback RESTORE %s: %w", ks.Key, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown snapshot strategy %q", data.Strategy)
	}
}
