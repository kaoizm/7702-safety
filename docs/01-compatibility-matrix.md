# Compatibility matrix: EIP-7702 security extensions

Status: draft, 2026-11-02. Every row cites a spec section; disagreements are
filed in [02-findings.md](02-findings.md).

## 1. Account code states

`raw` = value stored in the state trie. `EVM` = what CALL / EXTCODESIZE /
EXTCODECOPY observe after EIP-8476's refinement. `EXTCODEHASH` hashes that
EVM-visible code — `keccak256("")` for an opted-out account — while the
state-trie `codeHash` remains `keccak256(0xef0200)`.

| Raw code | Meaning | EVM sees | `ecrecover` (EIP-8151) | New 7702 authorization | ECDSA tx from sender |
| --- | --- | --- | --- | --- | --- |
| `0x` | plain EOA | `0x` | permitted | accepted | valid |
| `0xef0100 ‖ delegate` | EIP-7702 delegation | raw | permitted | accepted (re-delegates) | valid |
| `0xef0101 ‖ delegate` | EIP-7851, ECDSA burned | raw | **rejected** | **skipped** | **invalid** |
| `0xef0200` | EIP-8476 opt-out | `0x` (code); `keccak256("")` (EXTCODEHASH) | **rejected**[^draft] | **skipped** | valid |
| anything else | contract | raw | **rejected** | skipped (not an EOA) | invalid |

[^draft]: This row shows the behaviour of the **current EIP-8151 draft**, which
    is not activated. [ethereum/EIPs#12605](https://github.com/ethereum/EIPs/pull/12605)
    proposes accepting exactly `0xef0200` with unchanged gas accounting; that
    proposed behaviour is modelled separately and covered by the
    `eip8151_proposed` vectors. The EIP-8151 author supports the expected result
    but prefers EIP-8476 to specify the compatibility rule and leave EIP-8151
    unchanged; the normative location is unresolved (F-2).

Two rows are easy to confuse and matter operationally:

* `0xef0101` burns ECDSA but keeps wallet code in control; `0xef0200` keeps
  ECDSA but forbids delegation. They are **not** interchangeable.
* Under EIP-8151 **as drafted**, both `0xef0101` and `0xef0200` fail
  `ecrecover`, so `permit`-style approvals stop working for both. The EIP-8476
  author and an EIP-8151 author agree that opted-out accounts should retain
  ordinary ECDSA authorization. The EIP-8151 author prefers putting the
  compatibility rule in EIP-8476; both PRs remain open and the normative
  location is unresolved (F-2).

## 2. Operation × standard

| Operation | EIP-7702 | EIP-7851 | EIP-8151 | EIP-8476 | ERC-8010 |
| --- | --- | --- | --- | --- | --- |
| Set delegation | `0xef0100` auth | `SETSELFDELEGATE` | — | — | — |
| Revoke delegation | sign empty delegate | never (irreversible) | — | once, permanent | — |
| Trust a signature before delegation lands | no | no | no | no | **yes** (wrapped sig) |
| Detect a malicious delegation | `eth_getCode` | prefix check | — | marker check | — |
| Stop `permit` after migration | no | yes | **yes** | no | — |
| Stop future 7702 auths | no | yes | indirect | **yes** | — |
| Signature replay across chains | `chain_id` | — | — | **per-chain only** | — |

## 3. Decision guide

**Wallet holding user funds**

1. Never auto-approve an authorization tuple; decode `(chain_id, address, nonce)`.
2. Offer `0xef0200` opt-out for accounts that will never delegate.
3. If migrating to wallet code, prefer `0xef0101` only after confirming no
   `permit`-based integrations remain (under the current EIP-8151 draft those
   approvals fail).
4. Use ERC-8010 wrapped signatures when accepting signatures for accounts whose
   delegation has not landed yet.

**Exchange / custodian hot wallet**

1. Treat `eth_getCode(hotwallet) != 0x` as a pagable alert.
2. Opt out (`0xef0200`) on **every** chain the key can touch; a `chain_id = 0`
   authorization remains valid on chains where the account never transacted.
3. Enforce a pre-sign check that rejects type-4 transactions carrying an
   authorization list unless explicitly allowlisted.
4. Monitor for `0xef0101`; it is irreversible.

**Client / node**

1. `checkDelegationLimit` (geth legacypool) must treat `0xef0200` as empty-code.
2. `eth_getCode` returns the raw marker; the EVM must not execute it.
3. `eth_getProof` / `EXTCODEHASH` disagree for opted-out accounts — see F-6.

## 4. Per-chain caveat (the pattern behind the 29 Oct 2026 hot-wallet loss)

EIP-7702 authorizations with `chain_id = 0` are valid on every chain where the
authority's nonce matches. An opt-out is **strictly per chain**. Consequences:

* an opt-out on mainnet does not protect an L2 where the account never sent a
  transaction and the nonce is still 0;
* a fleet of hot wallets needs an opt-out transaction **per chain**, each
  requiring gas there;
* authorization batches can use a nonce range — a public chain analysis in the
  EIP-8476 thread describes one transaction carrying 50 tuples across 50
  consecutive nonces — so one tuple matches whatever the live nonce is.

## 5. Open interactions

| Interaction | Status |
| --- | --- |
| `0xef0200` applied to an account that already has `0xef0100` | defined: replaced directly (EIP-8476 `f1a4071`); suite applies it |
| `0xef0101` + `0xef0200` on the same account | cannot coexist (different code lengths) |
| ERC-8010 signature on an opted-out account | falls to the not-delegated branch; `init_to` call still executes |
| Native AA (EIP-8141 / 8130 / Tempo) replacing all of the above | tracks open; suite targets 7702-era semantics |
