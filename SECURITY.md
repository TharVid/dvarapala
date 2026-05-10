# Security Policy

## Reporting a vulnerability

Email **security@tharvid.in** with details. Please do not file public GitHub issues for security vulnerabilities.

We aim to:

- Acknowledge within 48 hours
- Provide a fix or mitigation timeline within 7 days
- Credit reporters in the release notes (unless anonymity is requested)

## Supported versions

During pre-1.0, only the latest minor version receives security patches.

## Threat model

Dvarapala is itself an enforcement boundary. Any vulnerability that allows:

- Bypassing policy enforcement
- Reading audit logs without authorization
- Tampering with the audit chain
- Privilege escalation in hub mode

…is critical. Other classes (e.g., crashes via malformed JSON-RPC) are high but non-critical.
