package adapters

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// respClient is a deliberately small RESP2 client.
//
// Why not a full library: the gateway sends a fixed vocabulary of commands and
// reads replies back, and every additional line of client code is a line an
// attacker gets to influence through a Redis reply. The reply parser below
// refuses nesting deeper than maxDepth and refuses bulk strings larger than
// maxBulk, so a hostile or corrupted server cannot exhaust the gateway's memory
// by answering a PING with a 4 GB blob.
type respClient struct {
	conn    net.Conn
	r       *bufio.Reader
	timeout time.Duration
}

const (
	maxDepth = 4
	maxBulk  = 4 << 20 // 4 MiB
)

type respError string

func (e respError) Error() string { return string(e) }

// dialRESP opens a connection, authenticates and selects a database.
func dialRESP(ctx context.Context, addr, username, password string, db int, timeout time.Duration) (*respClient, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial redis at %s: %w", addr, err)
	}
	c := &respClient{conn: conn, r: bufio.NewReaderSize(conn, 32*1024), timeout: timeout}

	if password != "" {
		args := []string{"AUTH", password}
		if username != "" {
			args = []string{"AUTH", username, password}
		}
		if _, err := c.do(ctx, args...); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("redis AUTH failed: %w", err)
		}
	}
	if db != 0 {
		if _, err := c.do(ctx, "SELECT", strconv.Itoa(db)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("redis SELECT %d failed: %w", db, err)
		}
	}
	return c, nil
}

func (c *respClient) Close() error { return c.conn.Close() }

// Do sends a command.
func (c *respClient) Do(ctx context.Context, args ...string) (any, error) {
	return c.do(ctx, args...)
}

func (c *respClient) do(ctx context.Context, args ...string) (any, error) {
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty redis command")
	}
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, a := range args {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteString("\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	if _, err := c.conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return c.readReply(ctx, 0)
}

func (c *respClient) readReply(ctx context.Context, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("redis reply nested deeper than %d levels", maxDepth)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	line, err := c.readLine()
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, fmt.Errorf("empty redis reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, respError(line[1:])
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("malformed integer reply %q", line)
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("malformed bulk length %q", line)
		}
		if n == -1 {
			return nil, nil
		}
		if n > maxBulk {
			return nil, fmt.Errorf("redis bulk reply of %d bytes exceeds the %d byte limit", n, maxBulk)
		}
		buf := make([]byte, n+2)
		if _, err := readFull(c.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("malformed array length %q", line)
		}
		if n == -1 {
			return nil, nil
		}
		if n > 1<<20 {
			return nil, fmt.Errorf("redis array reply of %d elements exceeds the limit", n)
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := c.readReply(ctx, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown redis reply type %q", line[0])
	}
}

func (c *respClient) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// stringify flattens a RESP reply into something safe to hand back.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return "(nil)"
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, stringify(e))
		}
		return "[" + strings.Join(parts, " ") + "]"
	default:
		return fmt.Sprint(t)
	}
}
