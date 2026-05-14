// Package envmode is the Go-side mirror of
// ``services/api/app/core/config.is_dev_env`` and friends.
//
// The same "dev mode" decision is made at multiple layers of the stack
// (Python API, Go ingest, Go enrichment), and the bugs we shipped pre-
// H-8 came from each layer hand-rolling its own slightly-different
// allow-list. This package is the single Go source of truth so a new
// dev alias (``staging-shadow``, ``preview``, ...) added in one place
// is visible to every other.
//
// Keep this in sync with
// ``services/api/app/core/config.DEV_ENVIRONMENTS``.
package envmode

import (
	"os"
	"strings"
)

// devEnvironments mirrors ``DEV_ENVIRONMENTS`` in the Python API
// settings. Update both at once if the canonical set changes.
var devEnvironments = map[string]struct{}{
	"development": {},
	"dev":         {},
	"local":       {},
	"demo":        {},
	"test":        {},
}

// Normalize lowercases and trims an env name so callers don't have to
// duplicate the same defensive cleanup. Exported so tests can hit it
// directly without depending on process state.
func Normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// IsDev reports whether the supplied env name is a development-class
// environment. Matches Python ``is_dev_env``.
func IsDev(value string) bool {
	_, ok := devEnvironments[Normalize(value)]
	return ok
}

// Current reads the live process environment, preferring ``ENV`` and
// falling back to ``ENVIRONMENT``. The two names are treated as
// aliases of each other — the Python settings model reconciles them
// at boot, but Go services that only consult ``os.Getenv`` need to
// see both forms or they will disagree with the API.
func Current() string {
	if v := os.Getenv("ENV"); v != "" {
		return Normalize(v)
	}
	return Normalize(os.Getenv("ENVIRONMENT"))
}

// IsDevRuntime is the convenience wrapper most callers want:
// ``IsDev(Current())``. Use this instead of bespoke
// ``os.Getenv("ENV") == "development"`` checks scattered around the
// codebase.
func IsDevRuntime() bool {
	return IsDev(Current())
}
