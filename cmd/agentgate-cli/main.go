// Command agentgate-cli is the operator side of AgentGate: issue scoped tokens,
// work the approval queue, read the audit chain, and replay a call.
//
// It exists so that approval does not require a browser. A change-management
// process that only works when someone remembers a URL is a process that gets
// bypassed, and a bypassed gateway is worse than no gateway.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/auth"
	"github.com/hd25071/AgentGate/internal/id"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentgate-cli:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`agentgate-cli -- operator tooling for the AgentGate gateway

  token secret                              generate values for AG_TOKEN_SECRET / AG_ADMIN_TOKEN
  token scopes                              list the scope catalogue
  token issue [flags]                       mint a scoped agent token
        --subject <name>   --scopes a,b     --ttl 1h
  approvals list [--status pending]         list approvals
  approvals show <id>                       show one approval
  approvals approve <id> --actor <you>      approve (quotes the action hash)
  approvals reject  <id> --actor <you>      reject
  audit tail [--limit 50]                   recent audit records
  audit verify                              verify the whole hash chain
  replay <request_id>                       print one call's full lifecycle
  tools                                     list tools advertised by the gateway
  call <tool> --args '<json>'               call a tool with an agent token

Connection comes from the environment:
  AG_URL            gateway base URL (default http://localhost:8080)
  AG_ADMIN_TOKEN    for /admin endpoints
  AG_TOKEN_SECRET   for 'token issue'
  AG_AGENT_TOKEN    for 'call'
`)
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage()
		return nil
	case "token":
		return tokenCmd(args[1:])
	case "approvals", "approval":
		return approvalsCmd(args[1:])
	case "audit":
		return auditCmd(args[1:])
	case "replay":
		return replayCmd(args[1:])
	case "tools":
		return toolsCmd(args[1:])
	case "call":
		return callCmd(args[1:])
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// ---------------------------------------------------------------------------
// token
// ---------------------------------------------------------------------------

func tokenCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("token requires a subcommand (secret|scopes|issue)")
	}
	switch args[0] {
	case "secret":
		t, err := id.NewToken(32)
		if err != nil {
			return err
		}
		a, err := id.NewToken(32)
		if err != nil {
			return err
		}
		fmt.Printf("AG_TOKEN_SECRET=%s\nAG_ADMIN_TOKEN=%s\n", t, a)
		fmt.Println("\nPut these in .env (never in the repo). AG_TOKEN_SECRET signs agent tokens;")
		fmt.Println("AG_ADMIN_TOKEN protects the approval API -- the two must be different.")
		return nil

	case "scopes":
		scopes := auth.KnownScopes()
		names := auth.ScopeNames()
		for _, n := range names {
			fmt.Printf("  %-14s %s\n", n, scopes[n])
		}
		return nil

	case "issue":
		fs := flag.NewFlagSet("token issue", flag.ExitOnError)
		subject := fs.String("subject", "", "token subject, e.g. redis-doctor")
		scopes := fs.String("scopes", "", "comma-separated scopes")
		ttl := fs.Duration("ttl", time.Hour, "token lifetime")
		secret := fs.String("secret", os.Getenv("AG_TOKEN_SECRET"), "signing secret")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *subject == "" || *scopes == "" {
			return fmt.Errorf("--subject and --scopes are required")
		}
		if *secret == "" {
			return fmt.Errorf("no signing secret: set AG_TOKEN_SECRET or pass --secret")
		}
		signer, err := auth.NewSigner([]byte(*secret), "agentgate")
		if err != nil {
			return err
		}
		token, claims, err := signer.Issue(*subject, strings.Split(*scopes, ","), *ttl)
		if err != nil {
			return err
		}
		fmt.Println(token)
		fmt.Fprintf(os.Stderr, "# subject=%s scopes=%s expires=%s jti=%s\n",
			claims.Subject, strings.Join(claims.Scopes, ","),
			time.Unix(claims.Expires, 0).Format(time.RFC3339), claims.TokenID)
		return nil

	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

func approvalsCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("approvals list", flag.ExitOnError)
		status := fs.String("status", "pending", "pending|approved|rejected|expired|executed|failed|all")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var out struct {
			Count     int `json:"count"`
			Approvals []struct {
				ID         string   `json:"id"`
				Status     string   `json:"status"`
				Risk       string   `json:"risk"`
				Summary    string   `json:"summary"`
				Subject    string   `json:"subject"`
				ActionHash string   `json:"action_hash"`
				Required   int      `json:"required_approvals"`
				Reasons    []string `json:"reasons"`
				CreatedAt  int64    `json:"created_at"`
			} `json:"approvals"`
		}
		if err := adminGet("/admin/approvals?status="+*status+"&limit=200", &out); err != nil {
			return err
		}
		if out.Count == 0 {
			fmt.Printf("no %s approvals\n", *status)
			return nil
		}
		for _, a := range out.Approvals {
			fmt.Printf("%s  [%s/%s]  %s\n", a.ID, a.Risk, a.Status, a.Summary)
			fmt.Printf("    agent=%s needs=%d created=%s\n", a.Subject, a.Required,
				time.UnixMilli(a.CreatedAt).Format(time.RFC3339))
			fmt.Printf("    reason: %s\n", strings.Join(a.Reasons, "; "))
			fmt.Printf("    action_hash=%s\n\n", a.ActionHash)
		}
		return nil

	case "show":
		if len(args) < 2 {
			return fmt.Errorf("approvals show requires an id")
		}
		var v any
		if err := adminGet("/admin/approvals/"+args[1], &v); err != nil {
			return err
		}
		return printJSON(v)

	case "approve", "reject":
		fs := flag.NewFlagSet("approvals "+args[0], flag.ExitOnError)
		actor := fs.String("actor", os.Getenv("AG_APPROVER"), "approver identity (cannot be the requesting subject)")
		comment := fs.String("comment", "", "change ticket or reason")
		hash := fs.String("hash", "", "action hash; defaults to the hash on file after showing it")

		// Same trap as `call`: the documented form is
		// `approvals approve <id> --actor <you>`, and flag.Parse stops at the
		// first positional argument, so --actor and --hash were silently
		// dropped and every approval failed with "an anonymous approval is not
		// an approval". Lift the id out first.
		apID := ""
		rest := args[1:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			apID = rest[0]
			rest = rest[1:]
		}
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if apID == "" {
			if tail := fs.Args(); len(tail) > 0 {
				apID = tail[0]
			}
		}
		if apID == "" {
			return fmt.Errorf("approvals %s requires an approval id", args[0])
		}
		if *actor == "" {
			return fmt.Errorf("--actor is required: an anonymous approval is not an approval")
		}

		actionHash := *hash
		if actionHash == "" {
			var ap struct {
				ActionHash string `json:"action_hash"`
			}
			if err := adminGet("/admin/approvals/"+apID, &ap); err != nil {
				return err
			}
			actionHash = ap.ActionHash
			fmt.Printf("approving action_hash=%s\n", action.ShortHash(actionHash))
		}

		body, _ := json.Marshal(map[string]any{
			"actor": *actor, "action_hash": actionHash, "comment": *comment,
		})
		var out any
		if err := adminPost("/admin/approvals/"+apID+"/"+args[0], body, &out); err != nil {
			return err
		}
		// Spell the past tense out. Deriving it by trimming a trailing "e" and
		// appending "d" produced "approvd" and "rejectd" -- an operator tool
		// that prints words that are not words reads as broken, and the one
		// message a person sees after approving should not be.
		verb := "approved"
		if args[0] == "reject" {
			verb = "rejected"
		}
		fmt.Printf("%s %s\n", verb, apID)
		return printJSON(out)

	default:
		return fmt.Errorf("unknown approvals subcommand %q", args[0])
	}
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

func auditCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"tail"}
	}
	switch args[0] {
	case "tail":
		fs := flag.NewFlagSet("audit tail", flag.ExitOnError)
		limit := fs.Int("limit", 50, "how many records")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var out struct {
			Records []struct {
				Seq       int64  `json:"seq"`
				Type      string `json:"type"`
				RequestID string `json:"request_id"`
				TS        int64  `json:"ts"`
				Payload   string `json:"payload"`
			} `json:"records"`
		}
		if err := adminGet(fmt.Sprintf("/admin/audit?limit=%d", *limit), &out); err != nil {
			return err
		}
		for _, r := range out.Records {
			fmt.Printf("#%-5d %-20s %s  %s\n", r.Seq, r.Type,
				time.UnixMilli(r.TS).Format("15:04:05.000"), truncate(r.Payload, 150))
		}
		return nil

	case "verify":
		var out struct {
			Valid    bool   `json:"valid"`
			Length   int64  `json:"length"`
			BrokenAt int64  `json:"broken_at"`
			Reason   string `json:"reason"`
			HeadHash string `json:"head_hash"`
		}
		err := adminGetRaw("/admin/audit/verify", &out)
		if err != nil {
			return err
		}
		if out.Valid {
			fmt.Printf("chain intact: %d records, head=%s\n", out.Length, out.HeadHash)
			return nil
		}
		fmt.Printf("chain BROKEN at record %d: %s\n", out.BrokenAt, out.Reason)
		return fmt.Errorf("audit chain verification failed")
	}
	return fmt.Errorf("unknown audit subcommand %q", args[0])
}

func replayCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("replay requires a request_id")
	}
	var out struct {
		Verified bool   `json:"chain_verified"`
		Broken   string `json:"chain_problem"`
		Records  []struct {
			Seq     int64  `json:"seq"`
			Type    string `json:"type"`
			TS      int64  `json:"ts"`
			Payload string `json:"payload"`
			Hash    string `json:"hash"`
		} `json:"records"`
	}
	if err := adminGet("/admin/replay/"+args[0], &out); err != nil {
		return err
	}
	if len(out.Records) == 0 {
		return fmt.Errorf("no records for request %s", args[0])
	}
	fmt.Printf("request %s\n", args[0])
	for _, r := range out.Records {
		fmt.Printf("\n#%d %s  %s\n", r.Seq, r.Type, time.UnixMilli(r.TS).Format(time.RFC3339Nano))
		fmt.Printf("  %s\n", prettyInline(r.Payload))
	}
	fmt.Printf("\nchain: %v %s\n", out.Verified, out.Broken)
	return nil
}

// ---------------------------------------------------------------------------
// MCP client
// ---------------------------------------------------------------------------

func toolsCmd(args []string) error {
	token := os.Getenv("AG_AGENT_TOKEN")
	if token == "" {
		return fmt.Errorf("AG_AGENT_TOKEN is required")
	}
	var out struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := mcpCall(token, "tools/list", map[string]any{}, &out); err != nil {
		return err
	}
	for _, t := range out.Result.Tools {
		fmt.Printf("%-28s %s\n", t.Name, truncate(t.Description, 110))
	}
	return nil
}

func callCmd(args []string) error {
	// The documented form is `call <tool> --args '<json>'`, and that is the
	// order a person actually types. Go's flag package stops parsing at the
	// first positional argument, so with the tool name in front the --args flag
	// was never parsed at all: every call silently went out with the default
	// empty object, and the gateway then refused it as an unparseable action,
	// blaming the caller's JSON for a bug in this tool. Lift the tool name out
	// first so both orders work.
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	rawArgs := fs.String("args", "{}", "tool arguments as JSON")

	tool := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		tool = args[0]
		rest = args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if tool == "" {
		if tail := fs.Args(); len(tail) > 0 {
			tool = tail[0]
		}
	}
	if tool == "" {
		return fmt.Errorf("call requires a tool name")
	}
	token := os.Getenv("AG_AGENT_TOKEN")
	if token == "" {
		return fmt.Errorf("AG_AGENT_TOKEN is required")
	}
	var in map[string]any
	if err := json.Unmarshal([]byte(*rawArgs), &in); err != nil {
		return fmt.Errorf("--args must be JSON: %w", err)
	}

	started := time.Now()
	var out struct {
		Result struct {
			IsError           bool           `json:"isError"`
			StructuredContent map[string]any `json:"structuredContent"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := mcpCall(token, "tools/call", map[string]any{"name": tool, "arguments": in}, &out); err != nil {
		return err
	}
	if out.Error != nil {
		return fmt.Errorf("gateway error %d: %s", out.Error.Code, out.Error.Message)
	}
	for _, c := range out.Result.Content {
		fmt.Println(c.Text)
	}
	fmt.Printf("\n-- structured (%s) --\n", time.Since(started).Round(time.Millisecond))
	return printJSON(out.Result.StructuredContent)
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

func baseURL() string {
	if v := os.Getenv("AG_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

func adminGet(path string, out any) error { return adminGetRaw(path, out) }

func adminGetRaw(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, baseURL()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Admin-Token", os.Getenv("AG_ADMIN_TOKEN"))
	return do(req, out)
}

func adminPost(path string, body []byte, out any) error {
	req, err := http.NewRequest(http.MethodPost, baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Admin-Token", os.Getenv("AG_ADMIN_TOKEN"))
	req.Header.Set("Content-Type", "application/json")
	return do(req, out)
}

func do(req *http.Request, out any) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var problem struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(raw, &problem) == nil && problem.Title != "" {
			return fmt.Errorf("%s (%s): %s", problem.Title, resp.Status, problem.Detail)
		}
		return fmt.Errorf("%s: %s", resp.Status, truncate(string(raw), 300))
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func mcpCall(token, method string, params map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id.New("cli"),
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL()+"/mcp", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	// Approval waits can be long; this is the one call that needs a wide window.
	client := &http.Client{Timeout: 6 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return json.Unmarshal(raw, out)
}

// ---------------------------------------------------------------------------
// output helpers
// ---------------------------------------------------------------------------

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func prettyInline(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return s
	}
	return truncate(string(b), 400)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
