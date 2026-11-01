# Copilot / agent instructions

This repository is an executable conformance suite for EIP-7702 security
standards. Full agent instructions live in [`AGENTS.md`](../AGENTS.md).

Non-negotiables:

- standard library only, no `pip install`
- `unittest`, not `pytest`
- `vectors/conformance.json` is generated; never hand-edit it
- every modeled rule cites an EIP section
- spec ambiguities become `F-N` findings, not silent guesses
- defensive only: no exploit tooling against live systems
