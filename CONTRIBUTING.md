# Contributing to IronMesh

Thank you for helping make device fleets safer. This guide covers the workflow, the quality bar,
and the conventions every change must meet.

## Ground rules

1. **The design contract is binding.** `docs/DESIGN_CONTRACT.md` defines identifiers, certificate
   profiles, topics, wire formats and service interfaces. A change to the contract is a breaking
   change: it needs an entry in `CHANGELOG.md`, updated test vectors in `device/common/vectors/`,
   and matching changes in the Rust agent, the ESP32 firmware and the Python reference library.
2. **No placeholders.** No `TODO`, `FIXME`, stubbed returns or "trust the client" shortcuts land on
   `main`. If a feature is incomplete, it stays on a branch.
3. **Security-relevant changes get a threat-model update.** If you touch authentication,
   authorization, crypto, parsing of untrusted input, or OTA, update `THREAT_MODEL.md` and run
   `python scripts/resolve_threat_refs.py --strict`.
4. **Tests are not optional.** Services keep >= 90% line coverage; the wire library >= 95%;
   firmware parsers have fuzz targets with committed corpora.

## Repository layout

| Path                   | What                                           | Language       |
|------------------------|------------------------------------------------|----------------|
| `services/pki`         | CA, EST, OCSP, CRL, revocation publisher       | Go             |
| `services/policy`      | EMQX authn/authz hooks, OPA policies, kick     | Go             |
| `services/bridge`      | MQTT -> Kafka bridge                           | Go             |
| `services/registry`    | Devices, twin, commands, config, audit         | Python         |
| `services/ota`         | Firmware signing, campaigns, rollouts          | Python         |
| `services/anomaly`     | Rules + Isolation Forest, quarantine, SIEM     | Python         |
| `libs/python/ironmesh-wire` | Reference CBOR/COSE/HPKE/delta             | Python         |
| `device/agent-rs`      | Linux agent and virtual fleet simulator        | Rust           |
| `device/esp32`         | ESP-IDF firmware                               | C              |
| `device/common`        | Wire specs and test vectors                    | Markdown/JSON  |
| `conformance`          | Conformance suite run against both targets     | Python         |
| `console`              | Fleet console                                  | TypeScript     |
| `deploy`               | docker compose, Helm, Kustomize, Terraform     | YAML/HCL       |
| `observability`        | OTel collector, Prometheus rules, dashboards   | YAML/JSON      |

## Development setup

```bash
# Go services
cd services/pki && make test
# Python (uses uv or venv; Python 3.12 64-bit)
python -m venv .venv && . .venv/bin/activate
pip install -e libs/python/ironmesh-wire[dev] -e services/registry[dev] -e services/ota[dev] -e services/anomaly[dev]
# Rust agent
cd device/agent-rs && cargo test
# Console
cd console && npm ci && npm run lint && npm run typecheck && npm test
# Everything, as CI runs it
make ci
```

See `HARDWARE_SETUP.md` for the ESP32 toolchain and the hardware-in-the-loop runner.

## Branching and commits

* Branch from `main`: `feat/<area>-<short>`, `fix/<area>-<short>`, `docs/<short>`, `sec/<short>`.
* Small, focused commits. Imperative subject line <= 72 chars, body explains *why*.
* Conventional prefixes are welcome but not required; the subject must make sense in `CHANGELOG.md`.
* Sign commits (`git commit -S`) if you have a key configured; CI verifies signatures on release
  tags.

## Pull requests

A PR must:

* pass CI: lint and type checks for every language, unit + integration + conformance tests, SAST
  (Semgrep, Bandit, gosec, cargo-audit), dependency scanning (Trivy), SBOM generation;
* include tests for new behaviour and for every bug fixed (regression test first);
* update documentation that the change affects (`README.md`, `ARCHITECTURE.md`, `RUNBOOK.md`,
  `COMPLIANCE_MATRIX.md` when a control changes);
* add a `CHANGELOG.md` entry under `Unreleased`;
* be reviewed by at least one maintainer from a different area when it touches a trust boundary
  (device <-> broker, broker <-> services, tenant isolation).

## Coding standards

* **Go**: `gofmt`, `go vet`, `golangci-lint` with the repo config; context on every I/O call;
  errors wrapped with `%w`; no `panic` outside `main` initialisation.
* **Python**: `ruff` (lint + format), `mypy --strict`, type hints everywhere, `pydantic` models at
  API boundaries, no bare `except`.
* **Rust**: `cargo fmt`, `cargo clippy -D warnings`, `#![forbid(unsafe_code)]` except in the
  TPM/OP-TEE FFI modules, which are reviewed line-by-line; all parsers have fuzz targets.
* **C (ESP-IDF)**: `-Wall -Wextra -Werror`, bounded buffers, every length checked before use,
  secrets zeroized with `explicit_bzero`/`mbedtls_platform_zeroize`, no dynamic format strings.
* **TypeScript**: `strict: true`, no `any`, ESLint + Prettier, React Server Components where
  possible, WCAG 2.2 AA (axe checks in CI).

## Security disclosures

Never open a public issue for a vulnerability. Follow `SECURITY.md`.

## Release process

1. Update `CHANGELOG.md`, bump versions (`VERSION` file, `Cargo.toml`, `pyproject.toml`,
   `package.json`, `device/esp32/version.txt` with incremented `version_code`).
2. Tag `vX.Y.Z`; CI builds and signs images and firmware, generates SBOMs, publishes release
   notes, and deploys to staging.
3. A maintainer approves the manual gate to production; the deploy workflow performs a canary
   rollout and auto-rolls back on SLO burn.

## Code of conduct

Be kind, be precise, assume good faith. Harassment of any kind is not tolerated; report concerns
to the maintainers at the security contact address.
