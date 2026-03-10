# ADR 0001: Support versioned runner plugins

- Date: 2026-03-10

## Context

The agent currently assumes every plugin speaks a single runner protocol and can be started through the `runner` dispense name and evaluated immediately.

The agent now supports a second plugin contract that requires an `Init` step before `Eval`. At the same time, it remains compatible with existing plugins and avoids forcing every deployment to update configuration when an OCI-published plugin can already advertise its protocol version.

## Decision

The agent supports explicit runner protocol versions per plugin and retains backward compatibility by defaulting to protocol version 1.

This is implemented by:

- adding `protocol_version` to plugin configuration
- defaulting unspecified plugins to protocol version 1
- reading `org.ccf.plugin.protocol.version` from OCI annotations for OCI plugin sources without an explicit `protocol_version`
- supporting only protocol versions 1 and 2
- mapping protocol version 1 to the `runner` dispense name and protocol version 2 to `runner-v2`
- calling `Init` before `Eval` for protocol version 2 plugins
- treating explicit configuration as authoritative over OCI metadata

## Consequences

### Positive

- Existing plugins continue to work without configuration changes.
- New plugins can adopt protocol version 2 and perform setup during `Init`.
- OCI-published plugins can self-describe their protocol version, reducing configuration drift.
- Unsupported or invalid annotations do not break execution; the agent logs and falls back to the configured or default version.

### Negative

- OCI-backed plugins may require an extra registry metadata lookup before execution.
- The agent now maintains two supported runner contracts instead of one.
- Plugin authors adopting protocol version 2 must implement `Init`.
