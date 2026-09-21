// Package version carries build metadata injected at link time.
package version

// Version is overridden with -ldflags "-X .../internal/version.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String renders a single-line build identifier for logs and /healthz.
func String() string {
	return Version + " (" + Commit + ", " + Date + ")"
}
