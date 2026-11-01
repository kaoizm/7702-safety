# 72-hour plan

Objective: a repo a spec author can clone, run, and cite — not a product.

## Hour 0–8 (done)

- [x] Repo scaffold, licence, README with the four-spec table
- [x] Dependency-free Keccak-256 + secp256k1 + RLP
- [x] `markers` classifier for `0xef0100` / `0xef0101` / `0xef0200`
- [x] EIP-7851 state-transition model
- [x] EIP-8151 precompile + gas model
- [x] EIP-8476 opt-out transition + visibility rules
- [x] ERC-8010 codec, parser, verifier procedure
- [x] all tests green

## Hour 8–24 (next)

- [x] `pytest`-free CI: GitHub Actions running `python run_tests.py` on 3.10/3.11/3.12
- [x] `vectors/conformance.json` schema documented (`vectors/README.md`)
- [x] vector replay test (`tests/test_vectors.py`): the JSON is consumed, not just compared
- [ ] Differential test: run the same vectors against `revm` via a Rust dev-dependency
- [ ] Draft the ERC-8010 pull request body (finding F-1 + test files)
- [ ] Post in the EIP-8476 Magicians thread with F-3 and F-4

## Hour 24–48

- [ ] `0xef0200` reference implementation as a Foundry test (no client needed):
      a mock state machine that mirrors `eip8476.py`
- [ ] Geth `checkDelegationLimit` patch proposal text (F-6)
- [x] `docs/04-threat-model.md`: signing-path failure taxonomy, incident as case study

## Hour 48–72

- [ ] Cross-chain replay scanner skeleton (`tools/scan_replay.py`), RPC-agnostic
- [ ] First measurement on mainnet + one L2, methodology documented
- [ ] Publish: X thread + ethresear.ch draft, linking the repo and F-1

## Follow-ups

- [ ] If `ethereum/EIPs#12605` merges, flip the `eip8151.ecrecover_precompile`
      default to `opt_out_eligible=True`, regenerate the vectors, and update the
      compatibility-matrix footnote so the default no longer describes the old
      draft.
- [ ] If ERC-8010's layout is resolved (F-1), pin the chosen order and remove
      the dual-layout codec path.

## Definition of done

1. `python run_tests.py` green on a clean machine with no pip install.
2. `vectors/conformance.json` regenerates byte-identically and is replayed by
   `tests/test_vectors.py`.
3. At least one spec author has reproduced a finding.
4. F-1 is filed where ERC-8010's authors will see it.
