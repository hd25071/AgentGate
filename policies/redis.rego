package agentgate.redis

import rego.v1

# ---------------------------------------------------------------------------
# Redis risk tiering.
#
# Every rule below reads normalized *features* (command_upper, is_eval,
# fragments, ...) produced by internal/action/redis.go. Nothing here inspects
# the raw command string, which is why "flushall", "F L U S H A L L" after
# whitespace folding, and "\x46LUSHALL" after escape decoding all land on the
# same rule.
# ---------------------------------------------------------------------------

# Commands that destroy a whole keyspace. Never approvable.
wipe_commands := {"FLUSHALL", "FLUSHDB", "SWAPDB"}

# Commands that can halt, corrupt or redirect the server process.
control_commands := {"SHUTDOWN", "DEBUG", "SLAVEOF", "REPLICAOF", "FAILOVER"}

# Commands that load code or change credentials.
code_and_auth_commands := {"MODULE", "ACL"}

# Commands that move data across instances.
transfer_commands := {"MIGRATE", "RESTORE"}

# CONFIG SET parameters that can turn a managed Redis into a foothold or an
# outage. Setting "dir"/"dbfilename" plus a RDB save is a well-known path to
# writing files on the host.
sensitive_config_params := {
	"dir",
	"dbfilename",
	"appendfilename",
	"logfile",
	"pidfile",
	"requirepass",
	"masterauth",
	"aclfile",
	"acl-pubsub-default",
	"protected-mode",
	"enable-debug-command",
	"enable-module-command",
	"rename-command",
	"bind",
	"unixsocket",
	"unixsocketperm",
	"cluster-config-file",
	"replicaof",
	"slaveof",
	"save",
	"appendonly",
	"maxmemory",
	"maxmemory-policy",
	"lua-time-limit",
	"enable-protected-configs",
}

# CONFIG GET on these returns live credentials.
credential_params := {"requirepass", "masterauth", "aclfile"}

deny contains reason if {
	cmd := input.action.args.command_upper
	cmd in wipe_commands
	reason := sprintf("redis: %s destroys an entire keyspace and has no rollback", [cmd])
}

deny contains reason if {
	cmd := input.action.args.command_upper
	cmd in control_commands
	reason := sprintf("redis: %s can halt, corrupt or repoint the server", [cmd])
}

deny contains reason if {
	cmd := input.action.args.command_upper
	cmd in code_and_auth_commands
	reason := sprintf("redis: %s loads code or rewrites credentials", [cmd])
}

deny contains reason if {
	cmd := input.action.args.command_upper
	cmd in transfer_commands
	reason := sprintf("redis: %s moves data across instances and cannot be undone here", [cmd])
}

# EVAL wraps arbitrary server-side Lua. There is no way to bound what it does,
# so the gateway refuses the wrapper entirely and expects a vetted script id.
deny contains reason if {
	input.action.args.is_eval == true
	reason := "redis: EVAL/EVALSHA/SCRIPT/FCALL executes arbitrary server-side code"
}

deny contains reason if {
	input.action.args.encoding_suspicious == true
	reason := "redis: command needed decoding (escape/percent/lookalike) before it could be read"
}

deny contains reason if {
	input.action.args.fragments > 1
	reason := sprintf("redis: payload carried %d commands but a tool call may carry exactly one", [input.action.args.fragments])
}

# Note the fold. `sensitive_config_params` is written in lower case, and Redis
# parameter names are case-insensitive, so the comparison must be lower-cased
# too. Comparing `upper(param)` against a lower-case set never matches, which
# silently downgraded `CONFIG SET dir /tmp` -- the classic RDB-write-to-host
# path -- from deny to "ask a human". The red-team report caught it by listing
# three CONFIG payloads as `deferred` instead of denied.
deny contains reason if {
	input.action.args.command_upper == "CONFIG"
	input.action.args.subcommand_upper == "SET"
	p := lower(input.action.args.config_param)
	p in sensitive_config_params
	reason := sprintf("redis: CONFIG SET %s changes server behaviour outside the data plane", [input.action.args.config_param])
}

deny contains reason if {
	input.action.args.command_upper == "CONFIG"
	p := lower(input.action.args.config_param)
	p in credential_params
	reason := sprintf("redis: CONFIG GET %s would hand the Agent a live credential", [input.action.args.config_param])
}

deny contains reason if {
	input.action.args.command_upper == "CONFIG"
	p := input.action.args.config_param
	p == "*"
	reason := "redis: CONFIG GET * dumps the entire server configuration including credentials"
}

deny contains reason if {
	input.action.args.command_upper == "MONITOR"
	reason := "redis: MONITOR streams every command issued on the instance"
}

deny contains reason if {
	input.action.args.command_upper == "KEYS"
	input.action.args.pattern == "*"
	input.action.blast_radius.production == true
	reason := "redis: KEYS * blocks the production server while scanning the whole keyspace"
}

deny contains reason if {
	input.action.args.command_known == false
	reason := sprintf("redis: %q is not in the gateway's known-command vocabulary, so the gateway cannot say what it does",
		[input.action.args.command_upper])
}

deny contains reason if {
	input.action.args.command_ascii == false
	reason := "redis: command name contained lookalike characters that are not valid Redis syntax"
}

# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

# Admin commands that only report state. Gating these would put a human in
# front of "how much memory is used", which is the cheapest possible way to
# teach an operator to approve without reading.
read_only_admin_commands := {"MEMORY", "SLOWLOG", "LATENCY", "COMMAND", "LASTSAVE"}

# CONFIG GET of one non-credential parameter is a read. This is the param-level
# half of the tiering: the command class is not the unit of judgement, the
# parameter is. `CONFIG GET *` and `CONFIG GET requirepass` stay denied above.
config_get_is_read if {
	input.action.args.command_upper == "CONFIG"
	input.action.args.subcommand_upper == "GET"
	input.action.args.config_param != "*"
	not lower(input.action.args.config_param) in credential_params
}

approval contains reason if {
	input.action.args.is_admin == true
	not input.action.args.command_upper in read_only_admin_commands
	not config_get_is_read
	reason := sprintf("redis: %s is a server-administration command", [input.action.args.command_upper])
}

approval contains reason if {
	input.action.args.command_upper == "KEYS"
	reason := "redis: KEYS blocks the server for the duration of the scan"
}

# A wildcard in a write or delete targets a set of keys nobody has enumerated.
# Note the rule does not depend on `pattern` being populated: reading a feature
# that only some code paths set is how a gate goes quietly dead, so the gate
# reads the fact (`has_wildcard`) and uses `pattern` for the message only.
approval contains reason if {
	input.action.args.has_wildcard == true
	input.action.verb in {"write", "delete"}
	reason := sprintf("redis: %s on wildcard pattern %q can touch an unbounded set of keys",
		[input.action.args.command_upper, input.action.resource.name])
}

approval contains reason if {
	input.action.args.key_count > 50
	reason := sprintf("redis: %d keys in a single call", [input.action.args.key_count])
}

flags contains reason if {
	input.action.args.has_wildcard == true
	reason := "redis: command uses a wildcard"
}

flags contains reason if {
	input.action.args.key_count > 10
	reason := sprintf("redis: touches %d keys", [input.action.args.key_count])
}

flags contains reason if {
	input.action.args.command_upper == "CONFIG"
	reason := "redis: server configuration surface"
}

# ---------------------------------------------------------------------------
# Allow reasons
#
# These are the positive half of the tiering. Without them the report can only
# say "allowed" for the actions the design *intends* to permit, which hides the
# difference between a deliberate permit and a rule that failed to fire.
# ---------------------------------------------------------------------------

allow contains reason if {
	input.action.verb == "read"
	input.action.args.command_upper
	reason := sprintf("redis: %s reads without mutating state", [input.action.args.command_upper])
}

allow contains reason if {
	input.action.verb in {"write", "delete"}
	input.action.blast_radius.scope == "key"
	input.action.blast_radius.affected <= 1
	reason := sprintf("redis: %s touches a single named key; the gateway snapshots it before executing, so the change can be undone",
		[input.action.args.command_upper])
}

allow contains reason if {
	input.action.verb in {"write", "delete"}
	input.action.blast_radius.scope == "key"
	input.action.blast_radius.affected > 1
	reason := sprintf("redis: %s touches %d named keys, all enumerated in the call; the gateway snapshots them before executing",
		[input.action.args.command_upper, input.action.blast_radius.affected])
}

allow contains reason if {
	input.action.args.command_upper in read_only_admin_commands
	reason := sprintf("redis: %s reports server state and mutates nothing", [input.action.args.command_upper])
}

allow contains reason if {
	config_get_is_read
	reason := sprintf("redis: CONFIG GET %s reads one non-credential parameter and changes nothing",
		[input.action.args.config_param])
}
