# Built-in rule packs

| Pack | What it catches | Library used |
|---|---|---|
| [`pii`](../policies/pii.yaml) | Emails, SSN, credit cards, phone, Aadhaar, PAN, IBAN, MRN, etc. | [Microsoft Presidio](https://github.com/microsoft/presidio) (sidecar) |
| [`secrets`](../policies/secrets.yaml) | AWS / GCP / Azure keys, GitHub / Slack tokens, JWT, private keys, .env | [gitleaks](https://github.com/gitleaks/gitleaks) (embedded Go lib) |
| [`prompt-injection`](../policies/prompt-injection.yaml) | Direct + indirect prompt injection | [llm-guard](https://github.com/protectai/llm-guard) + [Meta Prompt-Guard-86M](https://huggingface.co/meta-llama/Prompt-Guard-86M) |
| [`tool-poisoning`](../policies/tool-poisoning.yaml) | Malicious instructions in tool descriptions, line-jumping | **Dvarapala native** |
| [`tool-mutation`](../policies/tool-mutation.yaml) | Tool definitions changing between sessions (rug-pull) | **Dvarapala native** |
| [`destructive-actions`](../policies/destructive-actions.yaml) | `rm -rf`, `DROP TABLE`, `dd if=…of=/dev/sda`, etc. | **Dvarapala native** |
| [`egress-allowlist`](../policies/egress-allowlist.yaml) | Outbound HTTP from MCP servers to non-approved hosts | **Dvarapala native** |
| [`rate-limit`](../policies/rate-limit.yaml) | Per-tool, per-session rate limits | `golang.org/x/time/rate` |

## Adding your own

```yaml
defaults:
  - rulepack: my-org-pack   # loaded from /etc/dvarapala/policies/my-org-pack.yaml
```
