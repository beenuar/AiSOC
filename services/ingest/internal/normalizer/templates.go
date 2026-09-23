package normalizer

import "embed"

// InboxTemplates carries the vendor webhook templates into the binary.
//
// They used to be read from disk at INBOX_TEMPLATES_DIR, defaulting to
// /app/templates — a path the Dockerfile never populated, because the runtime
// stage copies only the compiled binary. So every deployment that got as far
// as configuring DATABASE_DSN still answered 503 for every template, and the
// failure surfaced as a warning at startup that nothing was watching.
//
// Embedding removes the class of bug rather than the instance: the templates
// are version-controlled beside the code that parses them, so they cannot be
// absent from an image, out of step with the binary, or pointed at the wrong
// directory. An operator can still add templates on disk — the registry loads
// these first and lets a same-named file on disk override one.
//
//go:embed templates/*.yaml
var InboxTemplates embed.FS

// InboxTemplateDir is the path prefix inside InboxTemplates.
const InboxTemplateDir = "templates"
