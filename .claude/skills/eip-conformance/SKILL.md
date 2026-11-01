---
name: eip-conformance
description: Use when adding or changing a spec model, test vector, or finding in this repository. Encodes the spec-first workflow and the repo's zero-dependency constraints.
metadata:
  origin: 7702-safety
---

# EIP conformance workflow

This skill keeps changes to `7702-safety` faithful to the specifications and
compatible with the repo's constraints (stdlib only, unittest, reproducible
vectors).

## When to activate

- Adding a new EIP/ERC model
- Adding or changing a conformance vector
- Filing a specification finding
- Reviewing a PR that changes on-chain semantics

## Procedure

1. **Locate the normative text.** Open the EIP/ERC and copy the exact sentences
   that define the behavior. Note the section heading. If the text is
   ambiguous, stop and go to step 6.
2. **Write the model as a pure function.** Frozen dataclasses in, frozen
   dataclasses out. No I/O, no globals, no clock, no randomness.
3. **Write the failing test first.** One test per rule, named after the rule,
   with a docstring quoting the spec sentence.
4. **Make it pass.** Keep the implementation smaller than the test.
5. **Add vectors.** Extend `tools/gen_vectors.py`, then run it and confirm
   `git status --short vectors/` is empty.
6. **Ambiguity protocol.** If two readings are defensible:
   - implement the reading that is safest for users,
   - expose the other reading as a distinct rejection reason,
   - add `F-N` to `docs/02-findings.md` with both quotes,
   - add a test named `test_spec_ambiguity_*`.
7. **Update the matrix.** `docs/01-compatibility-matrix.md` gets a row for any
   new code state or operation.

## Anti-patterns

- Guessing a gas value that the spec marks TBD
- Using `random` or time in a test
- Hand-editing `vectors/conformance.json`
- "Fixing" a spec by silently choosing an interpretation
- Adding `requests`, `web3`, or `pytest`

## Definition of done

`python run_tests.py` green, vectors reproducible, every new rule cited, and
any ambiguity filed as a finding.
