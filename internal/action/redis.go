package action

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// RedisNormalizer turns a redis-cli style invocation into a structured Action.
//
// The tool surface is intentionally narrow: one tool, "redis_exec", that takes
// a command string (or argv array). Everything interesting happens here,
// because "redis_exec" is simultaneously the most useful and the most
// dangerous tool an ops Agent can hold.
type RedisNormalizer struct{}

func (RedisNormalizer) Tool() string { return "redis_exec" }

// adminCommands are commands that reconfigure or control the server process
// rather than touch data. They are facts, not verdicts -- the verdict lives in
// policies/redis.rego.
var adminCommands = map[string]bool{
	"CONFIG": true, "CLIENT": true, "DEBUG": true, "ACL": true, "MODULE": true,
	"SCRIPT": true, "SHUTDOWN": true, "SLAVEOF": true, "REPLICAOF": true,
	"MIGRATE": true, "SWAPDB": true, "FAILOVER": true, "LATENCY": true,
	"MEMORY": true, "COMMAND": true, "MONITOR": true, "SAVE": true,
	"BGSAVE": true, "BGREWRITEAOF": true, "LASTSAVE": true, "SLOWLOG": true,
}

// writeCommands mutate data. Used to compute the verb and blast radius.
var writeCommands = map[string]bool{
	"SET": true, "SETEX": true, "SETNX": true, "PSETEX": true, "GETSET": true,
	"GETDEL": true, "GETEX": true, "APPEND": true, "SETRANGE": true, "INCR": true,
	"DECR": true, "INCRBY": true, "DECRBY": true, "INCRBYFLOAT": true,
	"MSET": true, "MSETNX": true, "HSET": true, "HSETNX": true, "HMSET": true,
	"HDEL": true, "HINCRBY": true, "LPUSH": true, "RPUSH": true, "LPOP": true,
	"RPOP": true, "LSET": true, "LTRIM": true, "LREM": true, "LINSERT": true,
	"SADD": true, "SREM": true, "SPOP": true, "SMOVE": true, "ZADD": true,
	"ZREM": true, "ZINCRBY": true, "ZPOPMIN": true, "ZPOPMAX": true,
	"ZREMRANGEBYRANK": true, "ZREMRANGEBYSCORE": true, "XADD": true, "XDEL": true,
	"XTRIM": true, "SETBIT": true, "BITFIELD": true, "PFADD": true, "PFMERGE": true,
	"GEOADD": true, "RESTORE": true, "COPY": true, "EXPIRE": true, "PEXPIRE": true,
	"EXPIREAT": true, "PERSIST": true, "RENAME": true, "RENAMENX": true,
	"DEL": true, "UNLINK": true, "FLUSHALL": true, "FLUSHDB": true,
}

// wholeKeyspaceCommands do not name a key at all; their blast radius is the
// entire dataset.
var wholeKeyspaceCommands = map[string]bool{
	"FLUSHALL": true, "FLUSHDB": true, "SWAPDB": true, "KEYS": true, "SCAN": true,
	"DBSIZE": true, "RANDOMKEY": true, "INFO": true,
}

// irreversibleCommands are the ones with no way back: they destroy data, run
// code the gateway cannot inspect, or change what the server *is*.
//
// This is deliberately not the same set as wholeKeyspaceCommands. Scope answers
// "how far does this reach"; irreversibility answers "can we undo it". KEYS and
// SCAN are wide but perfectly reversible -- reading every key leaves nothing to
// roll back -- and labelling them irreversible would do two kinds of damage: it
// would lie to the approver about the undo they are buying, and it would flood
// the approval queue with calls that need no judgement. An approval queue you
// can clear without reading is a rubber stamp, which is the exact failure the
// red-team harness measures.
var irreversibleCommands = map[string]bool{
	"FLUSHALL": true, "FLUSHDB": true, "SWAPDB": true,
	"SHUTDOWN": true, "DEBUG": true, "MIGRATE": true,
	"SLAVEOF": true, "REPLICAOF": true, "FAILOVER": true,
	"EVAL": true, "EVALSHA": true, "FCALL": true, "FCALL_RO": true,
}

// readCommands are side-effect-free reads.
var readCommands = map[string]bool{
	"GET": true, "MGET": true, "STRLEN": true, "EXISTS": true, "TYPE": true,
	"TTL": true, "PTTL": true, "EXPIRETIME": true, "PEXPIRETIME": true,
	"HGET": true, "HMGET": true, "HGETALL": true, "HKEYS": true, "HVALS": true,
	"HLEN": true, "HEXISTS": true, "HSTRLEN": true, "HRANDFIELD": true,
	"LLEN": true, "LRANGE": true, "LINDEX": true, "LPOS": true,
	"SCARD": true, "SMEMBERS": true, "SISMEMBER": true, "SMISMEMBER": true,
	"SRANDMEMBER": true, "SINTERCARD": true,
	"ZCARD": true, "ZRANGE": true, "ZSCORE": true, "ZRANK": true, "ZCOUNT": true,
	"XRANGE": true, "XREVRANGE": true, "XLEN": true, "XINFO": true,
	"GETRANGE": true, "BITCOUNT": true, "BITPOS": true, "GETBIT": true,
	"PFCOUNT": true, "DUMP": true, "OBJECT": true, "TOUCH": true,
	"SINTER": true, "SUNION": true, "SDIFF": true, "ZRANGEBYSCORE": true,
	"ZREVRANGE": true, "ZDIFF": true, "ZINTER": true, "ZUNION": true,
	"PING": true, "ECHO": true, "TIME": true, "LOLWUT": true, "WAIT": true,
}

// knownCommands is the closed vocabulary the gateway will forward.
//
// This is an allowlist, not a denylist, and it is the single most effective
// anti-bypass measure in the normalizer. A denylist has to anticipate every way
// a command can be spelled; an allowlist only has to admit the ones it
// recognises. "FLUSH ALL" with a stray space, an unknown vendor command, or a
// command invented by a future Redis release all fail the same way: the
// gateway does not know what they do, so it does not run them.
var knownCommands = buildKnownCommands()

func buildKnownCommands() map[string]bool {
	out := map[string]bool{}
	for _, set := range []map[string]bool{
		adminCommands, writeCommands, wholeKeyspaceCommands, readCommands,
	} {
		for k := range set {
			out[k] = true
		}
	}
	// Commands whose classification is handled by the explicit switch in
	// parseRedisCommand rather than by a feature table.
	for _, c := range []string{"EVAL", "EVALSHA", "FCALL", "FCALL_RO", "CONFIG", "DEBUG"} {
		out[c] = true
	}
	return out
}

func (RedisNormalizer) Normalize(args map[string]any, tgt Target) (*Action, error) {
	raw, err := redisRawCommand(args)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: redis_exec requires a non-empty command", ErrInvalidArgs)
	}

	fragments, primary := splitFragments(raw)
	feats, err := parseRedisCommand(primary)
	if err != nil {
		return nil, err
	}

	notes := []string{}
	if fragments > 1 {
		notes = append(notes, fmt.Sprintf("payload contained %d commands; only the first is classified", fragments))
	}

	verb := VerbRead
	switch {
	case feats.commandUpper == "":
		verb = VerbRead
	case adminCommands[feats.commandUpper]:
		verb = VerbConfig
	case writeCommands[feats.commandUpper] || feats.commandUpper == "EVAL" || feats.commandUpper == "EVALSHA" || feats.commandUpper == "FCALL":
		verb = VerbWrite
	}
	if feats.commandUpper == "DEL" || feats.commandUpper == "UNLINK" || feats.commandUpper == "FLUSHALL" || feats.commandUpper == "FLUSHDB" {
		verb = VerbDelete
	}
	if feats.commandUpper == "EVAL" || feats.commandUpper == "EVALSHA" || feats.commandUpper == "FCALL" || feats.commandUpper == "FCALL_RO" {
		verb = VerbExec
	}

	scope := ScopeKey
	if wholeKeyspaceCommands[feats.commandUpper] {
		scope = ScopeKeyspace
	}
	if feats.commandUpper == "FLUSHALL" {
		scope = ScopeDataset
	}

	affected := len(feats.keys)
	if scope != ScopeKey {
		affected = -1 // unbounded / unknown
	}

	irreversible := irreversibleCommands[feats.commandUpper]

	out := map[string]any{
		"command":          feats.command,
		"command_upper":    feats.commandUpper,
		"command_known":    knownCommands[feats.commandUpper],
		"command_ascii":    feats.commandASCII,
		"argv":             feats.argv,
		"fragments":        fragments,
		"key_count":        len(feats.keys),
		"touches_all_keys": wholeKeyspaceCommands[feats.commandUpper],
		"has_wildcard":     feats.hasWildcard,
		"is_admin":         adminCommands[feats.commandUpper],
		"is_write":         writeCommands[feats.commandUpper],
		"is_eval": feats.commandUpper == "EVAL" || feats.commandUpper == "EVALSHA" ||
			feats.commandUpper == "FCALL" || feats.commandUpper == "FCALL_RO" ||
			feats.commandUpper == "SCRIPT",
		"encoding_suspicious": feats.suspicious,
		"obfuscation_notes":   feats.notes,
	}
	if len(feats.keys) > 0 {
		out["set:keys"] = feats.keys
	}
	if feats.subcommand != "" {
		out["subcommand"] = feats.subcommand
		out["subcommand_upper"] = strings.ToUpper(feats.subcommand)
	}
	if feats.pattern != "" {
		out["pattern"] = feats.pattern
	}
	if feats.configParam != "" {
		out["config_param"] = feats.configParam
		out["config_param_upper"] = strings.ToUpper(feats.configParam)
	}
	if feats.evalBodyBytes > 0 {
		out["eval_body_bytes"] = feats.evalBodyBytes
	}
	if len(feats.rawArgv) > 0 {
		out["set:raw_argv"] = feats.rawArgv
	}
	if len(notes) > 0 {
		out["_notes"] = notes
	}

	a := &Action{
		Tool:   "redis_exec",
		Target: tgt,
		Verb:   verb,
		Resource: Resource{
			Type:  "key",
			Name:  feats.primaryKey(),
			Count: len(feats.keys),
		},
		Args: out,
		BlastRadius: BlastRadius{
			Scope:        scope,
			Affected:     affected,
			Irreversible: irreversible,
			Production:   strings.EqualFold(tgt.Env, "prod"),
		},
		Raw: raw,
	}
	if scope == ScopeKeyspace || scope == ScopeDataset {
		a.Resource.Type = "keyspace"
		a.Resource.Name = feats.pattern
	}
	if feats.commandUpper == "CONFIG" {
		a.Resource.Type = "server-config"
		a.Resource.Name = feats.configParam
	}
	if err := a.Seal(); err != nil {
		return nil, err
	}
	return a, nil
}

func redisRawCommand(args map[string]any) (string, error) {
	v, ok := args["command"]
	if !ok {
		return "", fmt.Errorf("%w: missing required argument %q", ErrInvalidArgs, "command")
	}
	switch t := v.(type) {
	case string:
		return t, nil
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, " "), nil
	case []string:
		return strings.Join(t, " "), nil
	default:
		return "", fmt.Errorf("%w: argument %q must be a string or array of strings", ErrInvalidArgs, "command")
	}
}

// splitFragments counts how many distinct commands a payload carries. An
// injected instruction frequently tries to smuggle a second command past
// single-command review.
func splitFragments(raw string) (int, string) {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	// Split on newlines and on ';' outside quotes.
	var parts []string
	for _, line := range strings.Split(normalized, "\n") {
		for _, seg := range splitUnquoted(line, ';') {
			if strings.TrimSpace(seg) != "" {
				parts = append(parts, seg)
			}
		}
	}
	if len(parts) == 0 {
		return 1, raw
	}
	return len(parts), parts[0]
}

func splitUnquoted(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
				continue
			}
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

type redisFeatures struct {
	command       string
	commandUpper  string
	subcommand    string
	argv          []string
	keys          []string
	rawArgv       []string
	pattern       string
	configParam   string
	hasWildcard   bool
	suspicious    bool
	notes         []string
	evalBodyBytes int

	// commandASCII reports whether the folded command name is printable ASCII.
	// Together with the known-command allowlist it separates "a command we do
	// not recognise" from "a string that only looks like a command" (a
	// homoglyph substitution). Those are different risks and the policy bundle
	// treats them differently.
	commandASCII bool
}

func (f redisFeatures) primaryKey() string {
	if len(f.keys) > 0 {
		return f.keys[0]
	}
	return ""
}

func parseRedisCommand(line string) (redisFeatures, error) {
	var f redisFeatures
	cleaned, notes, suspicious := deobfuscate(line)
	f.notes = notes
	f.suspicious = suspicious

	tokens, err := tokenizeRedis(cleaned)
	if err != nil {
		return f, err
	}
	if len(tokens) == 0 {
		return f, fmt.Errorf("%w: empty redis command", ErrInvalidArgs)
	}

	// A quoted command name can hide the real one: `"FLUSH ALL"` tokenizes to a
	// single token containing a space. Re-split so the command name is always a
	// single word and "FLUSH ALL" cannot slip past a "FLUSHALL" rule.
	if strings.ContainsAny(tokens[0], " \t") {
		head := strings.Fields(tokens[0])
		tokens = append(head, tokens[1:]...)
		f.notes = append(f.notes, "command name contained whitespace and was re-split")
	}

	f.argv = tokens
	f.command = tokens[0]
	f.commandUpper = strings.ToUpper(foldFullwidth(tokens[0]))
	f.rawArgv = tokens

	if f.commandUpper == "" {
		return f, fmt.Errorf("%w: unable to determine redis command name", ErrInvalidArgs)
	}

	// After folding, a command name outside printable ASCII is a confusable
	// substitution, not a Redis command. It is refused rather than guessed at.
	f.commandASCII = isPrintableASCII(f.commandUpper)
	if !f.commandASCII {
		f.suspicious = true
		f.notes = append(f.notes, "command name contains non-ASCII characters after folding (possible homoglyph substitution)")
	}

	rest := tokens[1:]
	switch f.commandUpper {
	case "CONFIG":
		if len(rest) > 0 {
			f.subcommand = rest[0]
			if strings.EqualFold(rest[0], "GET") || strings.EqualFold(rest[0], "SET") {
				if len(rest) > 1 {
					f.configParam = rest[1]
				}
			}
		}
	case "ACL", "CLIENT", "SCRIPT", "MODULE", "MEMORY", "COMMAND", "SLOWLOG", "DEBUG":
		if len(rest) > 0 {
			f.subcommand = rest[0]
		}
	case "KEYS":
		if len(rest) > 0 {
			f.pattern = rest[0]
			f.hasWildcard = strings.ContainsAny(rest[0], "*?[")
			f.keys = append(f.keys, rest[0])
		}
	case "SCAN":
		// SCAN without MATCH enumerates the whole keyspace.
		for i := 0; i < len(rest); i++ {
			if strings.EqualFold(rest[i], "MATCH") && i+1 < len(rest) {
				f.pattern = rest[i+1]
				f.hasWildcard = strings.ContainsAny(rest[i+1], "*?[")
			}
		}
	case "EVAL", "EVALSHA", "FCALL", "FCALL_RO":
		if len(rest) > 0 {
			f.evalBodyBytes = len(rest[0])
		}
		nkeys := 0
		if len(rest) > 1 {
			if n, err := strconv.Atoi(rest[1]); err == nil {
				nkeys = n
			}
		}
		for i := 0; i < nkeys && 2+i < len(rest); i++ {
			f.keys = append(f.keys, rest[2+i])
		}
	default:
		// Best-effort key extraction: for single-key commands the key is the
		// first positional argument. Commands that take a key later in argv are
		// handled by the explicit cases above; unknown commands are treated as
		// "at least one key" so policy still sees a resource.
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			f.keys = append(f.keys, rest[0])
		}
	}

	// Record the wildcard argument itself, not just the fact that one exists.
	// Policy gates wildcard writes, and the approval card needs to print the
	// pattern a human is signing off on.
	for _, k := range rest {
		if strings.ContainsAny(k, "*?[") {
			f.hasWildcard = true
			if f.pattern == "" {
				f.pattern = k
			}
		}
	}
	return f, nil
}

// tokenizeRedis splits a redis-cli style command line honouring single quotes,
// double quotes and backslash escapes.
func tokenizeRedis(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' && i+1 < len(s) {
				i++
				cur.WriteByte(unescape(s[i]))
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("%w: unterminated quote in redis command", ErrInvalidArgs)
	}
	flush()
	return tokens, nil
}

func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	default:
		return c
	}
}

// deobfuscate removes representation-level noise and records anything that
// looked like a deliberate attempt to defeat string matching. Normalization
// (case folding, whitespace collapsing, fullwidth folding) is *not* reported as
// suspicious -- that is the whole point of normalizing. Only transforms that
// change the byte stream in a way a human reviewer would not expect are flagged.
func deobfuscate(raw string) (string, []string, bool) {
	var notes []string
	suspicious := false
	s := raw

	if strings.ContainsRune(s, 0) {
		notes = append(notes, "payload contains NUL byte")
		suspicious = true
		s = strings.ReplaceAll(s, "\x00", "")
	}

	// Percent-encoding: %46%4C%55... -> FLU...
	if strings.Contains(s, "%") {
		if dec, ok := percentDecode(s); ok && dec != s {
			notes = append(notes, "payload contained percent-encoded octets")
			suspicious = true
			s = dec
		}
	}

	// Shell-style hex escapes: \x46\x4c...
	if strings.Contains(s, "\\x") || strings.Contains(s, "\\X") {
		if dec, ok := hexEscapeDecode(s); ok && dec != s {
			notes = append(notes, "payload contained \\x hex escapes")
			suspicious = true
			s = dec
		}
	}

	// Command substitution / shell metacharacters: an Agent that forwards a
	// log line verbatim into redis-cli can be made to run arbitrary shell.
	for _, meta := range []string{"$(", "`", "&&", "||", "$IFS", "\nsh ", ">/", "| "} {
		if strings.Contains(s, meta) {
			notes = append(notes, fmt.Sprintf("payload contains shell metacharacter %q", strings.TrimSpace(meta)))
			suspicious = true
		}
	}

	// Fullwidth / homoglyph folding is silent normalization, but only report it
	// when it actually changed something meaningful.
	if folded := foldFullwidth(s); folded != s {
		notes = append(notes, "command contained non-ASCII lookalike characters")
		s = folded
		suspicious = true
	}

	// Shell string concatenation: "FLU"+"SHALL". A command string is not a
	// shell script, so this construct has no legitimate reading here. Folding it
	// means the policy sees FLUSHALL instead of a harmless-looking token.
	if concatRe.MatchString(s) {
		notes = append(notes, "command used quoted string concatenation")
		suspicious = true
	}
	s = concatRe.ReplaceAllString(s, "")

	// Collapse runs of whitespace. Redis itself treats them as separators.
	s = strings.Join(strings.Fields(s), " ")
	return s, notes, suspicious
}

// concatRe matches `"a"+"b"` and `'a'+'b'`, the naive way to defeat a string
// matcher. It is applied before the whitespace pass so the join is seamless.
var concatRe = regexp.MustCompile(`(["'])\s*\+\s*(["'])`)

// isPrintableASCII reports whether every rune is a printable ASCII character.
func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r < 0x21 || r > 0x7E {
			return false
		}
	}
	return len(s) > 0
}

func percentDecode(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), changed
}

func hexEscapeDecode(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if (s[i] == '\\') && i+3 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			if raw, err := hex.DecodeString(s[i+2 : i+4]); err == nil {
				b.Write(raw)
				i += 3
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), changed
}

// confusables maps the lookalike code points that survive fullwidth folding.
// Cyrillic and Greek letters that render identically to Latin ones are the
// classic way to write "FLUSHALL" that no string comparison will match.
var confusables = map[rune]rune{
	// Cyrillic
	'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
	'О': 'O', 'Р': 'P', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'Ѕ': 'S', 'І': 'I',
	'Ј': 'J', 'а': 'a', 'в': 'b', 'с': 'c', 'е': 'e', 'н': 'h', 'к': 'k',
	'м': 'm', 'о': 'o', 'р': 'p', 'т': 't', 'у': 'y', 'х': 'x', 'і': 'i',
	// Greek
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
	'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'ο': 'o', 'ρ': 'p', 'ν': 'v', 'α': 'a', 'ε': 'e',
}

// foldFullwidth maps fullwidth, confusable and invisible code points onto ASCII.
func foldFullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			b.WriteRune(r - 0xFEE0)
		case r == 0x3000:
			b.WriteRune(' ')
		case unicode.Is(unicode.Cf, r):
			// zero-width joiners and friends
		default:
			if repl, ok := confusables[r]; ok {
				b.WriteRune(repl)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
