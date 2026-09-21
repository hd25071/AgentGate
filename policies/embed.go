// Package policies exposes the Rego policy bundle to the rest of the binary.
//
// The .rego sources are embedded so that a built gateway always carries its own
// policy: there is no deployment in which the binary starts without rules.
package policies

import "embed"

// FS holds every .rego file in this directory. Development builds may override
// it with --policy-dir, but the embedded copy is the default and the fallback.
//
//go:embed *.rego
var FS embed.FS
