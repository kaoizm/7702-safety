# Threat model: delegated-account signing paths

Scope: what can go wrong when an account's signing path is asked to approve an
EIP-7702 authorization, and which standard addresses which failure. Derived from
public incident data (29 Oct 2026 hot-wallet incident, EIP-8476 thread) and the
four drafts modelled in this repository.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Delegation authority | one signature can convert an EOA into attacker-controlled code |
| ECDSA private key | signs both transfers and authorizations |
| Signing pipeline | the only place where "should this be signed?" can be answered |
| Chain scope | a `chain_id = 0` authorization is valid on every 7702 chain |

## 2. Trust boundaries

```
[ user / operator ] -> [ wallet UI ] -> [ signer / HSM / MPC ] -> [ RPC ] -> chain
                                             ^
                                             +-- the boundary the incident crossed
```

The 29 Oct 2026 incident did not cross a cryptographic boundary. It crossed the
**decision** boundary: the signing pipeline saw a well-formed transaction and had
no rule that said "an authorization list is not a transfer".

## 3. Failure modes

| # | Failure | What it looks like on chain | Mitigation |
| --- | --- | --- | --- |
| T1 | Authorization indistinguishable from a transfer | amount and recipient columns are empty; the tuple changes *what the account is* | decode and display `(chain_id, delegate, nonce)` before signing; refuse unknown delegates |
| T2 | Pre-signed nonce-range batch | one transaction carrying N authorizations across consecutive nonces; 49 invalid, 1 valid | reject authorization lists on hot-wallet paths unless explicitly allowlisted |
| T3 | Long-lived delegation | delegation stays active for hours; revocation needs one signature and is often forgotten | alert on `eth_getCode != 0x`; auto-revoke runbook |
| T4 | Cross-chain replay | `chain_id = 0` tuple valid wherever the nonce matches, including chains never used | per-chain opt-out (EIP-8476) or explicit `chain_id` on every authorization |
| T5 | Delegation invisible in the wallet | user sees a normal tx; `0xef0100` never shown | surface raw code from `eth_getCode`/`eth_getProof` |
| T6 | ECDSA-disable confusion | `0xef0101` burns the key; `0xef0200` keeps it but blocks delegation | treat them as different states in every UI and policy |
| T7 | `permit` silently broken | opted-out account cannot use ERC-2612 flows under the current EIP-8151 draft | a cross-EIP rule must preserve `ecrecover` for `0xef0200`; normative location is under discussion (F-2) |

## 4. Control map

| Control | Standard | Status |
| --- | --- | --- |
| Permanent opt-out for accounts that never delegate | EIP-8476 | draft, PR open |
| Irreversible ECDSA burn after migration to wallet code | EIP-7851 | draft, opcode TBD |
| `ecrecover` respects account code state | EIP-8151 / EIP-8476 | current EIP-8151 draft rejects `0xef0200`; compatibility rule acknowledged, placement under discussion (F-2) |
| Signatures verifiable before delegation lands | ERC-8010 | draft, layout contradiction (F-1) |
| Client-side conformance vectors | this repo | shipped |

## 5. Residual risks

- A compromised signing path can still automate **ordinary** transactions; no
  standard here prevents that. Opt-out reduces amplification and persistence,
  not authority.
- Contracts holding assets that require the old delegate's code may become
  inaccessible after opt-out.
- The marker is per chain and irreversible; a mistaken opt-out needs a new
  account.
- On-chain contracts cannot distinguish an opted-out account from an ordinary
  EOA (EIP-8476 accepted tradeoff, F-6).

## 6. What this repository does not do

It does not detect, block, or exploit live delegations. It pins the intended
semantics so clients and wallets can implement the controls above and test them.
