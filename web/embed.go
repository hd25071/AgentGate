// Package web holds the embedded approval and replay UI.
//
// The page is a single self-contained HTML file with no external requests. It
// runs inside the gateway binary and is served from /admin/ui, so the review
// surface has no build step and no CDN dependency -- an ops console that needs
// the public internet to render is not an ops console.
package web

import "embed"

// FS holds the UI assets.
//
//go:embed index.html
var FS embed.FS
