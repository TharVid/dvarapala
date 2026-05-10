# Contributing to Dvarapala

Thanks for considering a contribution! Dvarapala aims to be the de-facto open-source security gateway for MCP.

## Ground rules

1. **We integrate, we don't reinvent.** If a battle-tested OSS library exists for what you want to detect (PII, secrets, prompt injection), wire it in instead of writing a new detector.
2. **MCP-specific attacks** (tool poisoning, line-jumping, tool mutation, etc.) are *our* novel contribution — those detectors live in `internal/detectors/`.
3. Every new detector must ship with test cases in `test/fixtures/attack-corpus/`.
4. Every public CLI flag must be documented in `docs/`.

## Development setup

```bash
git clone https://github.com/TharVid/dvarapala
cd dvarapala
make dev          # installs golangci-lint, goreleaser
make test         # unit tests
make lint         # gofmt + go vet + golangci-lint
make build        # build local binary into ./bin/dvarapala
```

## Pull request checklist

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] New detectors include attack-corpus fixtures
- [ ] New CLI flags are documented
- [ ] No new dependencies without justification (we prefer existing OSS)

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please **do not** open public issues for vulnerabilities.
