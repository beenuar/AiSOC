// Package ingestauth resolves which tenant a /v1/ingest request may write
// for, from the caller's credential rather than from a header the caller
// chose.
//
// Why this exists
// ---------------
// POST /v1/ingest/batch — the endpoint the README tells users to push
// telemetry to, and the one `make smoke` exercises — took its tenant from
// the X-Tenant-ID header and authenticated nothing. Any caller who could
// reach the port could write alerts into any tenant by typing that tenant's
// UUID. Compose binds the port to 127.0.0.1, which contains it locally, but
// ingesting real telemetry means exposing it, and nothing said so at the
// moment the operator did.
//
// Validating the header's *value* does not fix that. A UUID that parses is
// still a UUID the caller chose. The scope has to come from somewhere the
// caller does not control, which means the credential.
//
// This is a Go port of the semantics in services/api/app/security/
// tenant_scope.py, which the Python services already use for exactly this
// problem. Same two credential shapes, same intersection-only rule, same
// refusal on an empty scope. Keeping the reasoning identical across the two
// runtimes matters more than sharing code we cannot share.
package ingestauth

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Principal is the set of tenants one credential may write for, and what
// kind of credential said so.
//
// tenantIDs is authoritative and exhaustive. Nothing downstream may widen
// it, and no code path may substitute "every tenant" for an empty one —
// every cross-tenant leak this codebase has had took that shape, a scope
// that was absent rather than narrow and a write that read absent as
// "no filter".
type Principal struct {
	tenantIDs map[uuid.UUID]struct{}
	// Subject names the credential for logs. It is never the credential
	// itself: minted tokens are reduced to a trailing fingerprint.
	Subject string
	// Delegated is true when a service token asserted the tenant rather
	// than the credential carrying it. Surfaced so logs can tell a
	// trusted internal push apart from a tenant's own.
	Delegated bool
}

// NewPrincipal builds a principal over the given tenants. Passing none
// yields the empty principal, which refuses everything.
func NewPrincipal(subject string, delegated bool, ids ...uuid.UUID) Principal {
	set := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return Principal{tenantIDs: set, Subject: subject, Delegated: delegated}
}

// IsEmpty reports whether this credential authorises no tenant at all.
func (p Principal) IsEmpty() bool { return len(p.tenantIDs) == 0 }

// Covers reports whether this credential authorises writes for id.
func (p Principal) Covers(id uuid.UUID) bool {
	_, ok := p.tenantIDs[id]
	return ok
}

// Size is the number of tenants this credential reaches.
func (p Principal) Size() int { return len(p.tenantIDs) }

// placeholderTenantRefs are values that mean "the caller did not name a
// tenant" rather than naming one. Migration 001 seeds the canonical tenant
// with the *slug* "default" and the demo seed renames it, so the literal
// identifies nothing anywhere; treating it as a tenant named "default"
// would refuse every caller who simply left the field alone.
var placeholderTenantRefs = map[string]struct{}{
	"": {}, "default": {}, "none": {}, "null": {},
}

// ScopeError is returned when a write was attempted without a resolved
// tenant scope, or for a tenant outside the credential's scope. Callers
// surface it as 403: it means a write was about to run untenanted, or
// into somebody else's data.
type ScopeError struct{ msg string }

func (e *ScopeError) Error() string { return e.msg }

// Resolve returns the one tenant this request may write for, or refuses.
//
// Intersection only. A requested tenant inside the principal's scope is
// honoured — that is how a trusted service names the tenant it is acting
// for. A requested tenant outside it narrows to nothing and raises, rather
// than reaching outside. An empty requested value means "the caller's own
// tenant", which is the common case and the safe default.
func Resolve(p Principal, requested string) (uuid.UUID, error) {
	if p.IsEmpty() {
		return uuid.Nil, &ScopeError{"refusing to ingest with an empty tenant scope"}
	}

	if _, isPlaceholder := placeholderTenantRefs[strings.ToLower(strings.TrimSpace(requested))]; isPlaceholder {
		if p.Size() != 1 {
			return uuid.Nil, &ScopeError{
				fmt.Sprintf("credential reaches %d tenants; the request must name one", p.Size()),
			}
		}
		for id := range p.tenantIDs {
			return id, nil
		}
	}

	wanted, err := uuid.Parse(strings.TrimSpace(requested))
	if err != nil {
		return uuid.Nil, &ScopeError{"requested tenant is not a UUID"}
	}
	if !p.Covers(wanted) {
		return uuid.Nil, &ScopeError{"requested tenant is outside the credential's authorised scope"}
	}
	return wanted, nil
}
