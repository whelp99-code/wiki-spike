# ADR-0006 — Plugins are out-of-process, capability-bounded proposal workers

## Status
Accepted for P3-08.

## Context
Extensions are useful for parsing, transformation, and enrichment, but an in-process
plugin with direct DB, CAS, Git, key, or network access can bypass every Core policy.
Prompt or plugin manifest text is not an authorization boundary.

## Decision
1. The only accepted runner mode is `out_of_process`.
2. Core passes canonical request bytes to a `PluginRunner` interface; no storage object,
   connection, filesystem path, or signing key is exposed.
3. A content-bound manifest fixes plugin/version, allowed operations, required
   capabilities, maximum egress sensitivity, request/response byte limits, timeout,
   per-operation call quota, and output schema.
4. Workspace/actor capability, sensitivity clearance, manifest capabilities, egress,
   size, deadline, and quota are checked before invoking the runner.
5. Runner timeout or crash is isolated as `retry_later`; it cannot terminate Core.
6. Responses are bounded bytes, strict versioned JSON, identity-bound to the request and
   manifest, canonicalized, then checked by an allowlisted output schema validator.
7. Plugin output is a proposal/result only. It cannot publish a Generation or elevate
   provenance, sensitivity, or capabilities by itself.
8. Egress class `none` permits only an empty payload. Private or restricted data is sent
   only when both token clearance and manifest egress permit it.
9. Operation quotas are scoped by workspace, operation, and plugin.

## Consequences
- A concrete subprocess/container runner may be added without changing Core contracts.
- Retrying a failed plugin call consumes the operation budget unless a later policy
  explicitly grants a new operation.
- Manifest signing and historical registry validation are deferred to P3-09.
- External side effects remain outside PluginGateway and require a later ActionGateway.
