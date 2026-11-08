// Package policy embeds the Rego sources that the policy service evaluates.
//
// The files live next to this package in rego/ so that they can also be tested with the OPA CLI
// (`opa test policy/rego`). Files ending in _test.rego are OPA unit tests and are skipped when the
// production evaluator is built; see internal/hooks.
package policy

import "embed"

// FS contains every Rego module under rego/.
//
//go:embed rego/*.rego
var FS embed.FS

// Dir is the directory inside FS that holds the modules.
const Dir = "rego"
