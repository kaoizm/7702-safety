# Security policy

## Scope

This repository contains **defensive reference models and test vectors** for
EIP-7702 security standards. It ships no runtime service and holds no keys.

## Reporting a problem

Two kinds of reports are welcome:

1. **Conformance bugs** — an implementation or vector disagrees with a
   specification. Open an issue with the section number and the failing vector
   index.
2. **Specification ambiguity** — two defensible readings of a spec. Open an
   issue referencing `docs/02-findings.md` and the next free `F-N` id.

For anything that could affect a live deployment (exchanges, wallets, clients),
**do not open a public issue**. Use GitHub's private vulnerability reporting
(Security tab -> "Report a vulnerability") and give 14 days for coordination
before disclosure.

## Out of scope

- Exploit code against live systems
- Testnet/mainnet address lists for target selection
- Key material of any kind

## Disclosure timeline

| Day | Action |
| --- | --- |
| 0 | private report acknowledged |
| 7 | triage + affected standards identified |
| 14 | coordinated disclosure or agreed extension |
