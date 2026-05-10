# Attack corpus

Curated MCP attack scenarios used to evaluate Dvarapala's detection rate.

## Goals

- 200+ scenarios across the categories below
- Each scenario is a single JSON file conforming to `schema.json`
- Each has expected detection (`expected.action: deny|redact|require_approval|allow`)

## Categories

| Directory | Class | Source / inspiration |
|---|---|---|
| `tool-poisoning/` | Malicious instructions in tool description | Anthropic / HiddenLayer advisories |
| `line-jumping/` | Tool desc tries to override system prompt | Published MCP red-team writeups |
| `tool-mutation/` | Tool def changes between sessions | Adversarial scenarios |
| `indirect-prompt-injection/` | PI via tool output (file contents, URLs) | [garak](https://github.com/NVIDIA/garak) prompt-injection probes |
| `secrets-exfil/` | Tool tricked into leaking secrets / env | [PyRIT](https://github.com/Azure/PyRIT) |
| `destructive-actions/` | rm -rf / DROP TABLE / etc. on tool args | hand-crafted |
| `excessive-agency/` | Tool chains forming exfil paths | hand-crafted |

## Where corpus comes from (we don't reinvent)

- **garak** — NVIDIA's LLM vulnerability scanner, 100+ prompt-injection probes
- **PyRIT** — Microsoft's Python Risk Identification Toolkit
- **Anthropic / HiddenLayer / Lakera advisories** — published MCP attack writeups
- **OWASP LLM Top 10** — covers prompt injection, sensitive info disclosure, etc.

We curate, normalise to our schema, and translate to MCP context.
