#!/usr/bin/env python3
"""A tiny in-memory RESP2 server, used only to exercise the Redis adapter.

Why this exists: the red-team harness needs the guarded execution arm to be a
real execution, not a connection error. Docker is unavailable in this
environment, so a real Redis is not an option. This stub speaks enough of RESP2
to answer the commands the adapter issues (PING/TYPE/DUMP/PTTL/STRLEN/... and
the read/write commands that the benign task set uses), and it deliberately
replies `-ERR` to anything it does not implement, so a gap shows up as a gap
rather than as a silent success.
"""

import socket
import threading
import socketserver

HOST, PORT = "127.0.0.1", 16379

# key -> (type, value)
STORE: dict[str, tuple[str, object]] = {
    "session:42": ("string", "uid=4021;cart=3"),
    "session:99": ("string", "uid=7788;cart=0"),
    "cache:homepage": ("string", "<html>cached at build 4412</html>"),
    "feature:checkout_v2": ("string", "on"),
    "healthcheck": ("string", "ok"),
    "orders:1001": ("hash", {"id": "1001", "state": "paid", "total": "42.50"}),
    "orders:1002": ("hash", {"id": "1002", "state": "shipped", "total": "9.00"}),
    "queue:jobs": ("list", ["sync", "index", "email"]),
    "tags:hot": ("set", {"a", "b"}),
}

CONFIG = {
    "maxmemory": "0",
    "maxmemory-policy": "noeviction",
    "appendonly": "no",
    "save": "3600 1 300 100",
}

LOCK = threading.Lock()


def encode(value):
    """Render a Python value as a RESP2 reply."""
    if value is None:
        return b"$-1\r\n"
    if isinstance(value, bool):
        return b":1\r\n" if value else b":0\r\n"
    if isinstance(value, int):
        return b":%d\r\n" % value
    if isinstance(value, Simple):  # type: ignore[arg-type]
        return b"+" + str(value).encode() + b"\r\n"
    if isinstance(value, Error):
        return b"-" + str(value).encode() + b"\r\n"
    if isinstance(value, bytes):
        return b"$%d\r\n%s\r\n" % (len(value), value)
    if isinstance(value, str):
        raw = value.encode()
        return b"$%d\r\n%s\r\n" % (len(raw), raw)
    if isinstance(value, (list, tuple)):
        head = b"*%d\r\n" % len(value)
        return head + b"".join(encode(v) for v in value)
    return encode(str(value))


class Simple(str):
    pass


class Error(str):
    pass


def _match(pattern: str, key: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(key, pattern)


def handle(argv: list[str]):
    if not argv:
        return Error("ERR empty command")
    cmd = argv[0].upper()
    rest = argv[1:]

    with LOCK:
        if cmd == "PING":
            return Simple("PONG")
        if cmd in ("AUTH", "SELECT", "CLIENT", "SCRIPT", "HELLO"):
            return Simple("OK")
        if cmd == "TYPE":
            entry = STORE.get(rest[0]) if rest else None
            return Simple(entry[0] if entry else "none")
        if cmd == "DUMP":
            entry = STORE.get(rest[0]) if rest else None
            if not entry:
                return None
            # Not a real RDB payload; the adapter only base64s it and hands it
            # back to RESTORE, so a self-consistent blob is enough here.
            return ("STUBDUMP\x00" + rest[0]).encode()
        if cmd in ("PTTL", "TTL"):
            entry = STORE.get(rest[0]) if rest else None
            if not entry:
                return -2
            return -1 if cmd == "TTL" else -1
        if cmd == "EXISTS":
            return sum(1 for k in rest if k in STORE)
        if cmd == "DBSIZE":
            return len(STORE)
        if cmd == "GET":
            entry = STORE.get(rest[0]) if rest else None
            if not entry:
                return None
            return str(entry[1]).encode()
        if cmd == "SET":
            if len(rest) < 2:
                return Error("ERR wrong number of arguments for 'set'")
            STORE[rest[0]] = ("string", rest[1])
            return Simple("OK")
        if cmd == "DEL" or cmd == "UNLINK":
            n = 0
            for k in rest:
                if STORE.pop(k, None) is not None:
                    n += 1
            return n
        if cmd == "EXPIRE":
            return 1 if rest and rest[0] in STORE else 0
        if cmd == "KEYS":
            pat = rest[0] if rest else "*"
            return [_k.encode() for _k in sorted(STORE) if _match(pat, _k)]
        if cmd == "SCAN":
            pat = "*"
            if "MATCH" in [x.upper() for x in rest]:
                i = [x.upper() for x in rest].index("MATCH")
                if i + 1 < len(rest):
                    pat = rest[i + 1]
            keys = [_k.encode() for _k in sorted(STORE) if _match(pat, _k)]
            return [b"0", keys]
        if cmd == "STRLEN":
            entry = STORE.get(rest[0]) if rest else None
            return len(str(entry[1])) if entry else 0
        if cmd == "LLEN":
            entry = STORE.get(rest[0]) if rest else None
            return len(entry[1]) if entry and entry[0] == "list" else 0
        if cmd == "SCARD":
            entry = STORE.get(rest[0]) if rest else None
            return len(entry[1]) if entry and entry[0] == "set" else 0
        if cmd == "HLEN":
            entry = STORE.get(rest[0]) if rest else None
            return len(entry[1]) if entry and entry[0] == "hash" else 0
        if cmd == "ZCARD":
            return 0
        if cmd == "MEMORY":
            return 128
        if cmd == "LRANGE":
            entry = STORE.get(rest[0]) if rest else None
            if not entry or entry[0] != "list":
                return []
            vals = entry[1]
            start = int(rest[1]) if len(rest) > 1 else 0
            stop = int(rest[2]) if len(rest) > 2 else -1
            if stop < 0:
                stop = len(vals) + stop
            return [str(v).encode() for v in vals[start:stop + 1]]
        if cmd == "HGETALL":
            entry = STORE.get(rest[0]) if rest else None
            if not entry or entry[0] != "hash":
                return []
            out = []
            for k, v in entry[1].items():
                out.extend([k.encode(), str(v).encode()])
            return out
        if cmd == "SLOWLOG":
            return [["1", "1710000000", "12000", ["GET", "session:42"]]]
        if cmd == "INFO":
            return (
                "# Server\r\nredis_version:7.2.4-stub\r\nuptime_in_seconds:86400\r\n"
                "# Memory\r\nused_memory:1048576\r\nused_memory_peak:2097152\r\nmaxmemory:0\r\n"
                "# Stats\r\nevicted_keys:0\r\ntotal_commands_processed:1048576\r\n"
            ).encode()
        if cmd == "CONFIG":
            sub = rest[0].upper() if rest else ""
            if sub == "GET":
                param = rest[1] if len(rest) > 1 else ""
                if param in CONFIG:
                    return [param.encode(), CONFIG[param].encode()]
                return []
            if sub == "SET":
                if len(rest) < 3:
                    return Error("ERR wrong number of arguments for 'config|set'")
                CONFIG[rest[1]] = rest[2]
                return Simple("OK")
            return Error("ERR unknown CONFIG subcommand")
        if cmd == "RESTORE":
            STORE[rest[0]] = ("string", "<restored>")
            return Simple("OK")

    return Error("ERR this stub does not implement %s" % cmd)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        buf = b""
        while True:
            try:
                chunk = self.connection.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while True:
                argv, consumed = self.parse(buf)
                if argv is None:
                    break
                buf = buf[consumed:]
                try:
                    reply = encode(handle(argv))
                except Exception as exc:  # never let a stub bug look like a network error
                    reply = encode(Error("ERR stub failure: %s" % exc))
                self.connection.sendall(reply)

    @staticmethod
    def parse(buf: bytes):
        if not buf:
            return None, 0
        if buf[:1] != b"*":
            nl = buf.find(b"\r\n")
            if nl < 0:
                return None, 0
            line = buf[:nl].decode("utf-8", "replace")
            return line.split(), nl + 2
        nl = buf.find(b"\r\n")
        if nl < 0:
            return None, 0
        try:
            n = int(buf[1:nl])
        except ValueError:
            return [buf[:nl].decode("utf-8", "replace")], nl + 2
        pos = nl + 2
        out = []
        for _ in range(n):
            if pos >= len(buf) or buf[pos:pos + 1] != b"$":
                return None, 0
            nl = buf.find(b"\r\n", pos)
            if nl < 0:
                return None, 0
            ln = int(buf[pos + 1:nl])
            start = nl + 2
            if len(buf) < start + ln + 2:
                return None, 0
            out.append(buf[start:start + ln].decode("utf-8", "replace"))
            pos = start + ln + 2
        return out, pos


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as srv:
        print("resp stub listening on %s:%d" % (HOST, PORT), flush=True)
        srv.serve_forever()
