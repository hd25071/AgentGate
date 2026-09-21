// Package mcp implements the Model Context Protocol server surface.
//
// The gateway speaks MCP itself rather than sitting behind a proxy, for one
// reason: the protocol layer is where an Agent's tool call and the gateway's
// authenticated actor can be bound together in the same object. A pass-through
// proxy would have to re-derive identity from headers.
//
// The transport is JSON-RPC 2.0. The official Go SDK was reviewed and rejected
// for now: it is still moving, and the surface the gateway needs -- initialize,
// tools/list, tools/call, ping -- is a few hundred lines. Implementing it here
// removes a dependency from the trust boundary. See
// docs/adr/0001-gateway-design.md.
package mcp

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the revision this server implements.
const ProtocolVersion = "2025-06-18"

// SupportedProtocolVersions are accepted during initialize.
var SupportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// JSON-RPC error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	// -32000..-32099 is the implementation-defined range.
	CodeUnauthorized = -32001
	CodeDenied       = -32002
)

// Request is a JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the caller expects no reply.
func (r *Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// NewError builds an error object.
func NewError(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// MCP payload types
// ---------------------------------------------------------------------------

// ServerInfo identifies this server during initialize.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult is the initialize response.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

// Capabilities advertises what the server supports.
type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability advertises the tools capability.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

// Tool describes one callable tool.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	// Annotations follow the MCP convention so a host can warn before calling.
	Annotations map[string]any `json:"annotations,omitempty"`
}

// ListToolsResult is the tools/list response.
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// Content is one block of tool output.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// CallToolResult is the tools/call response.
type CallToolResult struct {
	Content []Content `json:"content"`
	// StructuredContent carries the machine-readable half. Agents that only
	// read text still work; agents that parse get stable field names.
	StructuredContent map[string]any `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

// TextResult builds a plain text result.
func TextResult(text string, structured map[string]any) CallToolResult {
	return CallToolResult{
		Content:           []Content{{Type: "text", Text: text}},
		StructuredContent: structured,
	}
}

// ErrorResult builds a failed-but-valid tool result.
//
// Policy denials are tool results, not protocol errors: the Agent needs to
// read the reason and adapt, and an MCP host that treats protocol errors as
// transport failures would hide the explanation from the model entirely.
func ErrorResult(text string, structured map[string]any) CallToolResult {
	r := TextResult(text, structured)
	r.IsError = true
	return r
}
