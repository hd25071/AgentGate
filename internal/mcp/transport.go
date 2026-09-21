package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

// Identity is the authenticated caller of a tool call.
type Identity struct {
	Subject string
	Scopes  []string
	Session string
	TokenID string
	// Raw is the presented token; kept only so the gateway can log its jti
	// rather than the token itself. Never logged directly.
	Raw string
}

type identityKey struct{}

// WithIdentity attaches an identity to a context.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom reads the identity, reporting whether one was present.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// ErrNoIdentity is returned when a request reaches a handler unauthenticated.
var ErrNoIdentity = errors.New("request is not associated with an authenticated identity")

// ---------------------------------------------------------------------------
// HTTP transport (MCP "streamable HTTP")
// ---------------------------------------------------------------------------

// AuthFunc authenticates an HTTP request and returns the identity.
type AuthFunc func(ctx context.Context, r *http.Request) (Identity, error)

// HTTPHandler serves MCP over a single POST endpoint.
//
// Both response encodings from the spec are supported: a plain JSON body when
// the client accepts it, and an SSE stream when the client insists on
// text/event-stream. Clients differ enough here that supporting only one of
// them breaks real integrations.
type HTTPHandler struct {
	srv  *Server
	auth AuthFunc
	log  *slog.Logger
}

// NewHTTPHandler builds the transport.
func NewHTTPHandler(srv *Server, auth AuthFunc, log *slog.Logger) *HTTPHandler {
	if log == nil {
		log = slog.Default()
	}
	return &HTTPHandler{srv: srv, auth: auth, log: log}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodGet:
		// This server is strictly request/response: it never pushes
		// server-initiated messages, so there is nothing to stream.
		w.Header().Set("Allow", "POST")
		http.Error(w, "this MCP endpoint is request/response only; use POST", http.StatusMethodNotAllowed)
	case http.MethodOptions:
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSONRPCError(w, nil, NewError(CodeParseError, "could not read request body"))
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONRPCError(w, nil, NewError(CodeParseError, "request body is not valid JSON-RPC"))
		return
	}

	ctx := r.Context()
	if h.auth != nil {
		id, err := h.auth(ctx, r)
		if err != nil {
			h.log.Info("mcp auth rejected", "remote", r.RemoteAddr, "err", err)
			writeJSONRPCError(w, req.ID, NewError(CodeUnauthorized, "%v", err))
			return
		}
		ctx = WithIdentity(ctx, id)
	}

	resp := h.srv.Handle(ctx, &req)
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		payload, err := json.Marshal(resp)
		if err != nil {
			return
		}
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Response{JSONRPC: "2.0", ID: id, Error: e})
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

// ServeStdio runs the server over newline-delimited JSON on a pair of streams.
//
// This is how a LangGraph or Claude-Desktop style host launches the gateway
// locally. The identity is fixed at startup because there is no per-request
// transport metadata on a pipe.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, id Identity) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)

	var mu sync.Mutex
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			mu.Lock()
			_ = enc.Encode(Response{JSONRPC: "2.0", Error: NewError(CodeParseError, "line is not valid JSON-RPC")})
			mu.Unlock()
			continue
		}
		reqCtx := WithIdentity(ctx, id)
		resp := s.Handle(reqCtx, &req)
		if resp == nil {
			continue
		}
		mu.Lock()
		err := enc.Encode(resp)
		mu.Unlock()
		if err != nil {
			return err
		}
	}
	return scanner.Err()
}
