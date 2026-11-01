# Findings

Issues found while turning the four specs into executable tests. Each is
reproducible with the suite. Severity is about *specification risk*, not
exploitability.

## F-1 — ERC-8010 signer and verifier layouts disagree (blocking)

**Where:** ERC-8010, "Signer Side" vs "Verifier Side".

Signer side:

```solidity
context = abi.encode(authorization, init_to, init_data)   // (bytes, address, bytes)
```

Verifier side:

```solidity
(authorization, init_data, init_to) = abi.decode(wrapped[..], (bytes, bytes, address))
```

Both the **order** (`init_to`/`init_data`) and the **ABI types**
(`(bytes,address,bytes)` vs `(bytes,bytes,address)`) differ. A signature
produced by any conforming signer cannot be parsed by a conforming verifier: the
address word is read as a dynamic offset and decoding reverts.

**Impact:** implementers will interoperate incorrectly, silently, per-wallet.
This is exactly the class of bug that makes a signature-verification standard
dangerous — two implementations disagreeing about *what was signed*.

**Repro:** `tests/test_erc8010.py::TestLayouts::test_spec_layouts_conflict` and
`::test_signer_wrapped_does_not_parse_as_verifier`.

**Suggestion:** pick `(authorization, init_to, init_data)` — the signer-side
order — and state the ABI types explicitly in both sections. Add the round-trip
vectors from `vectors/conformance.json`.

## F-2 — EIP-8151 cannot distinguish "no delegation" from "delegation disabled" (informational)

`is_permitted` only accepts empty code or `0xef0100 ‖ delegate`. Accounts with
`0xef0101` or `0xef0200` are rejected — which is the intent for `0xef0101`
(ECDSA burned) but means an opted-out account also fails `ecrecover`, breaking
`permit`-style flows for a wallet that merely wanted to disable delegation.
Verify this is intended before EIP-8476 ships; if not, EIP-8151's predicate
needs a second case.

## F-3 — EIP-8476 does not define opt-out over an existing delegation (blocking for implementers)

The draft says an opt-out installs `0xef0200` but does not say what happens when
the account already has `0xef0100` or `0xef0101`. Three defensible readings:
reject, take precedence, or require a two-step revoke-then-opt-out. The suite
rejects (`ACCOUNT_HAS_CODE`) to make the ambiguity visible instead of guessing.
This matters for exchange hot wallets, which are the stated motivation.

## F-4 — Cross-chain replay is under-specified in all four drafts

Only the EIP-8476 thread raises it (Zealynx, 2026-10-30): `chain_id = 0`
authorizations are valid on every 7702 chain where the nonce matches. No spec
defines a required "opt out everywhere" procedure, and EIP-8151/7851 say nothing
about chain scope. The suite models the per-chain rule; the measurement is
roadmap item 3.

## F-5 — EIP-7851 `SETSELFDELEGATE_OPCODE` is TBD

The parameter table still says `TBD`. Until an opcode is assigned, no client can
implement it and no bytecode can be written. The state-transition model here is
opcode-agnostic so it stays valid once a number is chosen.

## F-6 — EIP-8476's raw/EVM code split creates `EXTCODEHASH` divergence

Refinement (2026-10-31) keeps the marker in `eth_getCode`/`eth_getProof` while
the EVM sees empty code. That means `EXTCODEHASH(opted_out)` is neither the
empty-code hash nor `keccak256(0xef0200)` in a self-consistent way for every
consumer, and state proofs carry a code hash the EVM does not execute. Needs
explicit consensus-test coverage, not just prose.

## F-7 — No test vectors exist for any of the four drafts (the reason for this repo)

`EIP-7851`: none. `EIP-8151`: reference implementation, no vectors.
`EIP-8476`: none. `ERC-8010`: "Test Cases: TBD". This repository is the gap
filler; `vectors/conformance.json` is the first portable artifact.
