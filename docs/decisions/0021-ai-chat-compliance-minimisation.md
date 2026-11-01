# 0021. AI-chat compliance data is minimised by the schema, not by a promise

- **Status**: Accepted
- **Date**: 2026-11-01
- **Context**: depth plan wave 2, Phase 7.1
- **Supersedes / relates to**: ADR-0014 (tenant erasure crosses the audit trigger)

## Context

Enterprise AI assistants now publish compliance APIs that return an
organisation's whole conversation history: who said what to which model, in
which project, with the message bodies. A SOC has a real reason to read
them — a credential pasted into a chat is an incident, and nobody finds it
by waiting for the credential to be used — and no good reason to keep them.

The plan's sentence for this phase is "for content store only classification
labels and a bounded snippet, never full conversations". That sentence,
written into a design document and then implemented against a `TEXT` column,
is not a control. It holds exactly as long as every future caller remembers
it. The first one who binds `"\n".join(messages)` into that column succeeds,
silently, and the platform now holds a conversation store that its own
documentation says does not exist.

This repository has the matching precedent in the other direction: a
docstring promising that `evidence_fingerprint` excluded volatile fields,
while its only caller hashed the whole raw event. The promise was true of
nobody's code.

## Decision

The minimisation is expressed in the database schema and in the public
surface of the client, so that storing a conversation requires a change
somebody has to write and review.

1. **There is no column that can hold a message.** `migration 146` creates
   four record tables and none of them has a `body`, `content`, `text`,
   `message`, `transcript`, `conversation`, `prompt` or `completion` column.
   `test_ai_chat_compliance_minimisation.py` asserts the absence against the
   ORM, which is what application code binds through.
2. **The snippet is `VARCHAR(280)`.** The collector truncates; the column is
   the backstop for the caller that forgets. 280 characters is enough for a
   reviewer to tell a pasted `.env` from a sentence about rotating a key, and
   is not enough to read a conversation.
3. **The snippet is masked before it is cut.** Every matched span is
   replaced by its shape name, so a row that says "this chat contained an AWS
   access key" does not contain the key. A verbatim window would create a new
   copy of the secret, in a table an operator believes is safe to keep, and
   label it so an attacker can find it. A per-pattern test sweeps every shape
   in the shared list and asserts the value is absent from the snippet.
4. **The label vocabulary is a CHECK constraint.** Four values, enforced by
   the database. An unconstrained label column is how a classifier ends up
   storing the matched value as a label.
5. **The client has no method that returns message text.** `classify_chat`
   reads the messages inside one call, hands them to the classifier and
   returns a `Classification`. No caller can reach the conversation, even by
   accident. A test asserts the public surface, because this is the kind of
   property a later convenience method silently removes.
6. **Two opt-ins, with the stricter one the default.** `enabled` turns on the
   directory and the activity feed. `content_labels_enabled` covers anything
   derived from message text and is `FALSE` by default even when the first is
   on. A tenant that wants its activity feed and explicitly does not want
   message bodies read gets that without discovering a setting.
7. **Off by default, per tenant, through the console.** No environment
   variable and no YAML knob. A tenant with no configuration row is not
   collected from. The key is the tenant's own, vault-encrypted before the
   row is written, and a vault failure is a 503 rather than a plaintext row.

## Retention, legal hold and erasure

Every table carries a column named exactly `tenant_id`, which is how
`tenant_deletion.discover_tenant_tables` finds it. Discovery rather than a
declared list is deliberate: a list is the thing that goes stale, and a
table outside erasure says nothing about being outside it. ADR-0014's
erasure path therefore covers these tables the day they are created, and a
test asserts the column name on each one.

`collected_at` is what the retention purge clocks off, and `legal_holds`
outranks it through the existing `may_purge` decision. These tables are no
different from alerts there, which is the point — a second retention
mechanism for this data would be a second thing to get wrong.

`DELETE /ai-chat-compliance/config?purge=true` is the per-tenant erasure a
data-subject request needs without deleting the tenant. Disabling without
purging is the default, because an operator turning a feature off should not
silently destroy evidence an open investigation may rest on.

## Consequences

**Accepted.** A reviewer investigating a labelled chat has 280 masked
characters and must go to the provider's own console for the conversation.
That is the intended cost: the provider is where the conversation lives, under
the customer's own access controls and their own audit trail, and a copy in
AiSOC would be a second place to breach.

**Accepted.** The classifier runs on text held only in memory, so a label is
as good as its patterns and there is no corpus to re-score against later. A
pattern added next year does not retroactively label last year's chats. The
alternative — keeping the text so it can be re-scored — is the thing this
ADR exists to refuse.

**Accepted.** `aisoc_ai_chat_content_labels` holds one row per chat rather
than per message. A per-message table would be a message index, which is
most of the way to a conversation store by a different name.

**Rejected: encrypting conversations at rest instead of discarding them.**
Envelope encryption (`vault:v2:`) exists in this tree and would have made a
conversation store defensible on paper. It does not change the answer to
"what does a reader of this database get", because the service that reads
the table holds the key. Not storing it is the only form of this that
survives a database dump.

**Rejected: a deployment-wide switch.** Collection reaches a third party's
API with a customer's key about a customer's staff. The decision belongs to
the tenant, in their console, against their own key, and nowhere else.
