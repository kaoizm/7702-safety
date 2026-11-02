# Findings

Issues found while turning the four specs into executable tests. Each is
reproducible with the suite. Severity is about *specification risk*, not
exploitability.

Status is tracked against the upstream drafts as of 2026-11-02:
EIP-8476 at `ethereum/EIPs#12600` head `44c146e`, ERC-8010 at
`ethereum/ERCs#1186` head `6e5290c`, EIP-7851/8151 at their published drafts.

## F-1 — ERC-8010 signer and verifier layouts disagree (BLOCKING, open)

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
(`(bytes,address,bytes)` vs `(bytes,bytes,address)`) differ. A signature produced
by a conforming signer cannot be parsed by a conforming verifier: depending on
`init_to`, decoding either reverts or — worse — silently mis-parses. For the
spec-permitted `init_to = 0`, the zero word is read as dynamic offset 0, so the
authorization bytes come back as `init_data` and verification proceeds against
garbage instead of failing loudly.

**Impact:** implementers will interoperate incorrectly, silently, per-wallet.
This is exactly the class of bug that makes a signature-verification standard
dangerous — two implementations disagreeing about *what was signed*.

**Repro:** `tests/test_erc8010.py::TestLayouts::test_spec_layouts_conflict` and
`::test_signer_wrapped_does_not_parse_as_verifier`.

**Reported:** `ethereum/ERCs#1186` (comment), repo issue #1.

**Suggestion:** pick `(authorization, init_to, init_data)` — the signer-side
order — and state the ABI types explicitly in both sections. Add the round-trip
vectors from `vectors/conformance.json`.

## F-2 — EIP-8151's predicate rejects the EIP-8476 marker (ACKNOWLEDGED; placement under discussion)

EIP-8151's `ecrecover` restriction accepts only:

```
is_permitted = len(code) == 0 or (len(code) == 23 and code[:3] == 0xef0100)
```

An EIP-8476 opted-out account has raw code `0xef0200`, so `ecrecover` returns
empty for it. Every `permit`-style flow (ERC-2612 and friends) then fails for an
account that EIP-8476 says "continues to behave as an ordinary EOA at the EVM
level".

EIP-8476 `f1a4071` acknowledges the compatibility requirement. The EIP-8476
author initially asked for the predicate change in EIP-8151, and the proposal
was opened as [ethereum/EIPs#12605](https://github.com/ethereum/EIPs/pull/12605).
On 2026-11-02, EIP-8151 author Colinlyguo said the expected behavior looks good
but recommended specifying the extension in EIP-8476 and leaving EIP-8151
unchanged. The normative location is now under discussion; the expected result
is not disputed. The compatible predicate, independent of which EIP owns it, is:

```python
is_permitted = (
    len(code) == 0
    or (len(code) == 23 and code[:3] == b"\xef\x01\x00")
    or code == b"\xef\x02\x00"
)
```

**Repro:** `tests/test_eip8151.py::TestECRecoverRestriction::test_opt_out_marker_rejected`
(current behavior) and `tests/test_markers.py::TestEip8151Predicate`.

**Suggestion:** the two specifications must define a consistent result before
either activates, regardless of activation order. The authors are considering
whether EIP-8151 owns the predicate exception (#12605) or EIP-8476 owns the
cross-EIP compatibility rule. Keep the model's default and proposed behaviors
separate until that normative placement is settled.

**Status (2026-11-02):** the EIP-8476 author and EIP-8151 author agree that an
opted-out account should retain ordinary ECDSA authorization, including
`ecrecover`-based flows such as ERC-2612 `permit`. The EIP-8476 author reviewed
the proposed predicate in #12605 and confirmed it matches the intended
semantics. Colinlyguo then recommended putting the compatibility rule in
EIP-8476 and leaving EIP-8151 unchanged. EIP-8476 PR #12600 includes combined
test cases, while #12605 still proposes an EIP-8151 text change. Both PRs remain
open, so **no normative change has been accepted**. The default model continues
to represent current EIP-8151 draft behavior; the expected compatible behavior
is opt-in (`allow_eip8476_opt_out_marker=True`, vectors section
`eip8151_proposed`).

## F-3 — EIP-8476 over an existing delegation (RESOLVED upstream)

Originally the draft did not say what happens when `0xef0200` is applied to an
account that already has `0xef0100`. Revision `f1a4071` states: *"An existing
EIP-7702 delegation is replaced directly; no preliminary clearing transaction is
required."* The model now follows this
(`tests/test_eip8476.py::test_replaces_existing_delegation`).

One edge remains worth pinning: an EIP-7851 `0xef0101` account cannot originate
an ECDSA transaction, so the transition `0xef0101 -> 0xef0200` is unreachable.
If it ever became reachable it would re-enable ECDSA authority and break
EIP-7851's irreversibility invariant. The suite rejects it explicitly
(`test_ecdsa_disabled_sender_rejected`).

## F-4 — Cross-chain replay (ADDRESSED upstream)

The EIP-8476 draft now has an explicit per-chain paragraph: the marker exists
only in the chain where the opt-out ran, a `chain_id = 0` authorization stays
valid on every other 7702 chain where the account has not opted out and the
nonce matches, and an owner must opt out on each chain including ones never
used, funding gas there first.

The operational measurement is still missing from the ecosystem and remains
roadmap item 3 (`tools/scan_replay.py`).

## F-5 — EIP-7851 `SETSELFDELEGATE_OPCODE` is TBD (open)

The parameter table still says `TBD`. Until an opcode is assigned, no client can
implement it and no bytecode can be written. The state-transition model here is
opcode-agnostic so it stays valid once a number is chosen.

## F-6 — EIP-8476's raw/EVM code split and `EXTCODEHASH` (ACKNOWLEDGED upstream)

Revision `f1a4071` explicitly accepts the divergence: the state-trie
`codeHash` differs from `EXTCODEHASH` for marked accounts, and on-chain
contracts cannot distinguish an opted-out account from an ordinary EOA. It is
documented as a deliberate tradeoff to preserve ERC-721/1155 receiver hooks.
No action for this suite beyond keeping the visibility model tested
(`tests/test_eip8476.py::test_evm_sees_empty_but_rpc_sees_marker`).

## F-7 — No test vectors existed for any of the four drafts (the reason for this repo)

`EIP-7851`: none. `EIP-8151`: reference implementation, no vectors.
`EIP-8476` at `f1a4071` now has a 27-row Test Cases table (it did not at first
draft); the vectors here are being reconciled against it. Its repeat-opt-out row
is exactly what exposed the wrong gas in this repo's first EIP-8476 model.
`ERC-8010`: "Test Cases: TBD". `vectors/conformance.json` remains the first
portable, machine-checked artifact, and `tests/test_vectors.py` replays it.
