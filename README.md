# 7702-safety

[![CI](https://github.com/kaoizm/7702-safety/actions/workflows/ci.yml/badge.svg)](https://github.com/kaoizm/7702-safety/actions/workflows/ci.yml)

**An executable conformance suite for the EIP-7702 security standards.**

The 29 October 2026 hot-wallet incident was not a cryptographic break. A signing
path that could not answer *"should this transaction be signed?"* accepted an
EIP-7702 authorization tuple, and one valid signature turned the hot wallet into
an attacker-controlled contract. Public chain analysis in the EIP-8476 thread
describes the sequence; Binance has not published a root cause.

Four standards exist today to close that gap:

| Standard | Purpose | Gap |
| --- | --- | --- |
| [EIP-7851](https://eips.ethereum.org/EIPS/eip-7851) | Code-controlled delegation (`0xef0101`), permanent ECDSA burn | opcode TBD, no tests |
| [EIP-8151](https://eips.ethereum.org/EIPS/eip-8151) | Account-code restricted `ecRecover` | no tests |
| [EIP-8476](https://ethereum-magicians.org/t/eip-8476-permanent-eoa-delegation-opt-out/30134) | Permanent opt-out marker (`0xef0200`) | no reference implementation; draft has a 27-row Test Cases table |
| [ERC-8010](https://github.com/ethereum/ERCs/pull/1186) | Pre-delegation signature verification | *Test Cases: TBD*, *Security Considerations: TBD* |

This repository is an independent verification layer: **portable JSON test
vectors, a dependency-free executable reference, and a compatibility matrix**
that any client team, wallet, or auditor can run. The vectors are replayed by
`tests/test_vectors.py`, so they cannot silently drift from the models.

## Quick start

```powershell
python -m unittest discover -s tests -v
python tools/gen_vectors.py
```

No pip install. No Foundry required. Python 3.10+ standard library only.

## Layout

```
src/w7702/
  crypto/keccak.py      Keccak-256 (Ethereum padding), pure Python
  crypto/secp256k1.py   Sign / public-key recovery, pure Python
  crypto/rlp.py         Minimal RLP for authorization tuples
  authorization.py      EIP-7702 authorization signing hash (0x05 || rlp(...))
  markers.py            Code classification: 0xef0100 / 0xef0101 / 0xef0200
  eip7851.py            SETSELFDELEGATE state-transition model
  eip8151.py            ecRecover account-code restriction + gas model
  eip8476.py            Opt-out marker state transition + EVM visibility rules
  erc8010.py            Wrapped-signature codec + verification procedure model
tests/                  One file per standard, plus crypto self-tests
vectors/                Generated, portable conformance vectors (JSON)
docs/                   Compatibility matrix, findings, roadmap
```

## Status

- [x] `0xef0100` / `0xef0101` / `0xef0200` classifier
- [x] EIP-7851 state-transition model + validation rules
- [x] EIP-8151 precompile model (gas + account-code restriction)
- [x] EIP-8476 opt-out transition, EVM-visibility and txpool rules
- [x] ERC-8010 codec, parser and verifier procedure
- [ ] Client-level (geth / revm) differential tests
- [ ] Cross-chain `chain_id = 0` replay measurement

## Findings so far

Seven specification issues are documented in
[docs/02-findings.md](docs/02-findings.md). Current status:

- **F-1 — open, blocking.** ERC-8010's signer-side and verifier-side context
  layouts disagree on both field order and ABI types; a conforming signer cannot
  be parsed by a conforming verifier. Reported on `ethereum/ERCs#1186`.
- **F-2 — compatibility acknowledged; specification location unresolved.** The
  current EIP-8151 draft rejects `0xef0200` in `ecrecover`, breaking `permit`-
  style flows for opted-out accounts. Both the EIP-8476 author and EIP-8151
  author support preserving those flows, but the EIP-8151 author prefers
  specifying the exception in EIP-8476 and leaving EIP-8151 unchanged. PRs
  [ethereum/EIPs#12605](https://github.com/ethereum/EIPs/pull/12605) and
  [ethereum/EIPs#12600](https://github.com/ethereum/EIPs/pull/12600) remain open;
  no normative change has been accepted, so both behaviours stay modelled.
- **F-3, F-4 — resolved** in EIP-8476 revision `f1a4071`; **F-6** acknowledged
  there as a deliberate tradeoff; **F-5** is an upstream gap (opcode TBD), not an
  action for this repo.

Scope note: the models are validated against the specifications and replayed
against the published vectors. They are **not yet differentially tested against
geth/revm**; that is roadmap item 3, not a current claim.


## For contributors and agents

- [AGENTS.md](AGENTS.md) — operating rules for any AI agent (humans too)
- [CONTRIBUTING.md](CONTRIBUTING.md) — PR expectations
- [SECURITY.md](SECURITY.md) — disclosure policy
- [.claude/skills/eip-conformance/SKILL.md](.claude/skills/eip-conformance/SKILL.md) — repo-specific skill

Every claim in `docs/` cites a spec section. If a test disagrees with a spec,
the spec wins — open an issue with the section number.

Licensed MIT. Docs CC0.
