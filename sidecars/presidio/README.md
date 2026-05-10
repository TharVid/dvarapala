# Presidio sidecar

Dvarapala uses **Microsoft Presidio** for PII/PHI/PCI detection and redaction.
We do not run our own regexes for these classes — Presidio is the industry-standard
OSS tool, supports HIPAA / GDPR / PCI, and has 50+ built-in recognizers.

There is no custom Dockerfile in this directory because Microsoft publishes
official images:

```
mcr.microsoft.com/presidio-analyzer:latest
mcr.microsoft.com/presidio-anonymizer:latest
```

The compose file at `examples/docker-compose/docker-compose.yml` wires both
into the Dvarapala stack on ports 3000 (analyzer) and 3001 (anonymizer).

Dvarapala calls the analyzer over HTTP from `internal/detectors/pii/`. See
that package for the integration.

## Custom recognizers (Indian PII, etc.)

Drop YAML files into `recognizers/` for Aadhaar, PAN, GSTIN, IFSC, etc.
Presidio loads them at startup. Sample recognizer:

```yaml
- name: in_aadhaar
  supported_language: en
  patterns:
    - name: aadhaar_pattern
      regex: '\b\d{4}\s?\d{4}\s?\d{4}\b'
      score: 0.85
  context: [aadhaar, "आधार", uidai]
  supported_entity: IN_AADHAAR
```
