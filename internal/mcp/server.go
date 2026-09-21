package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// ToolHandler executes one tool call.
//
// args is the raw argument object from the Agent. Implementations must treat it
// as hostile input -- that is the entire premise of the project.
type ToolHandler func(ctx context.Context, args map[string]any) (CallToolResult, error)

// registeredTool pairs a tool's schema with its handler.
type registeredTool struct {
	tool    Tool
	handler ToolHandler
}

// Server is a minimal MCP server.
type Server struct {
	name    string
	version string

	mu    sync.RWMutex
	tools map[string]registeredTool
	order []string

	// Instructions is returned by initialize to tell a host how to behave.
	instructions string
}

// NewServer builds an empty server.
func NewServer(name, version string) *Server {
	return &Server{name: name, version: version, tools: map[string]registeredTool{}}
}

// SetInstructions customises the initialize hint.
func (s *Server) SetInstructions(text string) { s.instructions = text }

// Add registers a tool. Registering an existing name replaces it, which keeps
// test setups simple.
func (s *Server) Add(t Tool, h ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[t.Name]; !exists {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = registeredTool{tool: t, handler: h}
}

// Tools lists registered tools in registration order.
func (s *Server) Tools() []Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tool, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.tools[name].tool)
	}
	return out
}

// HasTool reports whether a tool exists.
func (s *Server) HasTool(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tools[name]
	return ok
}

// Handle dispatches one JSON-RPC request.
//
// A nil *Response means the request was a notification and the caller should
// send nothing back.
func (s *Server) Handle(ctx context.Context, req *Request) *Response {
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeInvalidRequest, "jsonrpc must be \"2.0\"")}
	}
	if req.Method == "" {
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeInvalidRequest, "method is required")}
	}

	switch req.Method {
	case "initialize":
		return s.reply(req, s.handleInitialize(req.Params))
	case "notifications/initialized", "notifications/cancelled", "notifications/progress":
		return nil // notifications are acknowledged by silence
	case "ping":
		return s.reply(req, map[string]any{})
	case "tools/list":
		return s.reply(req, ListToolsResult{Tools: s.Tools()})
	case "tools/call":
		return s.handleToolCall(ctx, req)
	case "resources/list":
		return s.reply(req, map[string]any{"resources": []any{}})
	case "prompts/list":
		return s.reply(req, map[string]any{"prompts": []any{}})
	default:
		if req.IsNotification() {
			return nil
		}
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeMethodNotFound, "method %q is not supported", req.Method)}
	}
}

func (s *Server) reply(req *Request, result any) *Response {
	if req.IsNotification() {
		return nil
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *Server) handleInitialize(params json.RawMessage) InitializeResult {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)

	version := ProtocolVersion
	for _, supported := range SupportedProtocolVersions {
		if p.ProtocolVersion == supported {
			version = supported
			break
		}
	}
	return InitializeResult{
		ProtocolVersion: version,
		Capabilities:    Capabilities{Tools: &ToolsCapability{ListChanged: false}},
		ServerInfo:      ServerInfo{Name: s.name, Version: s.version},
		Instructions:    s.instructions,
	}
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (s *Server) handleToolCall(ctx context.Context, req *Request) *Response {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeInvalidParams, "params did not decode: %v", err)}
	}
	if p.Name == "" {
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeInvalidParams, "params.name is required")}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}

	s.mu.RLock()
	rt, ok := s.tools[p.Name]
	s.mu.RUnlock()
	if !ok {
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeMethodNotFound, "unknown tool %q", p.Name)}
	}

	result, err := rt.handler(ctx, p.Arguments)
	if err != nil {
		// Handlers return errors only for genuine transport problems; anything
		// the Agent should read comes back as an isError result.
		return &Response{JSONRPC: "2.0", ID: req.ID, Error: NewError(CodeInternalError, "%v", err)}
	}
	if result.Content == nil {
		result.Content = []Content{{Type: "text", Text: "(no output)"}}
	}
	if req.IsNotification() {
		return nil
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// ToolNames returns registered names, sorted. Used by tests and the healthz page.
func (s *Server) ToolNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]string(nil), s.order...)
	sort.Strings(out)
	return out
}

// String renders a debug summary.
func (s *Server) String() string {
	return fmt.Sprintf("mcp.Server(%s/%s, %d tools)", s.name, s.version, len(s.order))
}
