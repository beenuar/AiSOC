# FIPS 140-3 posture

**AiSOC does not ship FIPS 140-3 validated cryptography, and cannot be made
to by configuration.** If your programme requires validated modules, this
page tells you exactly what would have to change rather than leaving you to
discover it during an assessment.

Saying so plainly is the point. "FIPS-compliant" is a phrase vendors use to
mean anything from "validated module" to "we use AES", and an assessor who
discovers the difference late is an assessor who no longer believes the rest
of the answers.

## What is actually used

| Purpose | Primitive | Provider | Validated? |
|---------|-----------|----------|------------|
| Credential encryption (`vault:v1`) | AES-128-CBC + HMAC-SHA256 (Fernet) | `cryptography` / OpenSSL | No |
| Credential encryption (`vault:v2`) | AES-128-CBC per-secret DEK, KEK in AWS KMS | `cryptography` + KMS | KMS side: yes |
| Backup encryption | AES-256-GCM | `cryptography` / OpenSSL | No |
| Audit hash chain | SHA-256 | `hashlib` / OpenSSL | No |
| Session tokens | HMAC-SHA256 (JWT) | `PyJWT` / `hashlib` | No |
| Sandbox determinism | BLAKE2b | `hashlib` | **Not a FIPS algorithm** |
| TLS | Whatever the deployment terminates with | Operator's choice | Operator's choice |

Every algorithm except BLAKE2b is FIPS-*approved*. None of the
implementations is FIPS-*validated*, and those are different claims: an
approved algorithm run through an unvalidated module does not satisfy FIPS
140-3.

BLAKE2b is used in one place — the sandbox's deterministic reasoner — where
it is a stable numeric hash for reproducibility, not a security control. It
protects nothing and would be swapped for SHA-256 without consequence if the
rest of the stack were ever validated.

## What validation would require

Not a configuration flag. In rough order of effort:

1. **A validated cryptographic module.** Building `cryptography` against a
   FIPS-validated OpenSSL, or moving to a provider that ships one, and
   pinning it in every image. Six Python services and two JavaScript ones
   each link their own.
2. **FIPS mode enforced, not merely available.** A module in FIPS mode
   rejects non-approved algorithms at call time. That surfaces every
   incidental use — including BLAKE2b above, and any transitive dependency
   reaching for MD5 in a non-security context, which several libraries do
   for cache keys.
3. **An audit of transitive dependencies.** `PyJWT`, `passlib`,
   `neo4j`, `clickhouse-driver` and the Kafka clients all perform
   cryptographic operations. Each needs checking against the validated
   module rather than assumed.
4. **A validated base image**, since the OS-level OpenSSL is what most of
   the above resolves to.
5. **Evidence that it stays that way.** A CI gate asserting FIPS mode is on
   and no non-approved algorithm is reachable — otherwise the posture
   regresses on the first dependency bump and nobody notices.

## If you need FIPS today

The honest options, in the order most organisations find useful:

- **Terminate TLS with a validated appliance or load balancer.** Data in
  transit is the requirement most programmes actually enforce, and it is
  satisfiable outside the application.
- **Use `vault:v2` with AWS KMS.** Key wrapping then happens inside a
  validated HSM even though the per-secret DEK operation does not. This is a
  genuine improvement in posture, and it is not full validation — the DEK
  still encrypts and decrypts through the unvalidated local module.
- **Encrypt backups at the storage layer** with a validated KMS, rather than
  relying on `backup_crypt.py`. Set `BACKUP_ENCRYPTION=off` and let the
  bucket do it. The manifest and integrity checking still apply.
- **Treat the platform as out of scope** and place the FIPS boundary
  elsewhere in the architecture. This is what most deployments do, and it is
  a defensible position provided it is written down rather than assumed.

## Status

Out of scope for v8.x. Not on the roadmap, because the work is large, the
demand has not been expressed by a deployment, and listing it as planned
would be the same kind of claim this page exists to avoid.

If you need it, open an issue describing the programme requirement. A named
requirement from a real deployment is what would change the calculation.
