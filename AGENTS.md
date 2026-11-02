# AGENTS.md

Instructions for any AI coding agent (Claude Code, Codex, Cursor, Copilot, DSH)
working in this repository. Read this before editing anything.

## What this repository is

An **executable conformance suite** for the EIP-7702 security standards
(EIP-7851, EIP-8151, EIP-8476, ERC-8010). It is not a product and has no
runtime dependencies. The artifacts are: models, tests, portable vectors,
and findings.

## Commands

```bash
python run_tests.py          # full suite, unittest
python tools/gen_vectors.py  # regenerate vectors/conformance.json
```

There is no `pip install`. There is no `pytest`. There is no `package.json`.

## Hard rules

1. **Standard library only.** Adding a dependency requires a written
   justification in the PR description and a maintainer decision. The value of
   this repo is that a spec author can clone it and run it with a bare Python.
2. **`unittest`, not `pytest`.** Do not introduce fixtures, plugins, or
   `conftest.py`.
3. **Vectors must be reproducible.** `tools/gen_vectors.py` must produce a
   byte-identical `vectors/conformance.json`. CI enforces
   `git diff --exit-code -- vectors/`. Never hand-edit a vector file.
4. **Deterministic tests.** Signatures use explicit nonces. No randomness, no
   clock, no network in tests.
5. **Every behavior cites the spec.** A docstring or comment that states a rule
   must name the EIP and the section. If the spec is silent, do **not** invent
   behavior — model the ambiguity explicitly and open a finding (`F-N`).
6. **One finding per ambiguity.** Append to `docs/02-findings.md` with the next
   free `F-N` id, the spec quote, impact, and a reproducible test name.
7. **No exploit tooling.** This repo is defensive. Nothing here may target live
   systems, third-party addresses, or real keys. Test fixtures use synthetic
   addresses and published test keys only.
8. **Findings are constructive.** When a spec is ambiguous, the tone is
   "which did you mean, here are vectors for both", never "you are wrong".
9. **Documentation layers move together.** A behavioural change updates, in the
   same commit: the module docstring, the function docstring,
   `docs/01-compatibility-matrix.md`, and the vectors. A new flag or code state
   must be described at every layer that still states the old behaviour.

## Layout

```
src/w7702/crypto/   keccak, secp256k1, rlp  (pure Python, audited against vectors)
src/w7702/*.py      one module per standard
tests/              one test module per standard, plus crypto self-tests
tools/              vector generation
vectors/            generated, portable, schema in vectors/README.md
docs/               compatibility matrix, findings, roadmap, threat model
```

## Adding a new standard (recipe)

1. Add `src/w7702/eipXXXX.py` with a pure-function state-transition model.
   No I/O, no globals. Return frozen dataclasses.
2. Add `tests/test_eipXXXX.py` covering: the happy path, every rejection
   reason, and the interaction with at least one other standard.
3. Add a section to `tools/gen_vectors.py` and regenerate.
4. Extend `docs/01-compatibility-matrix.md` with a row and an operation.
5. If the spec is ambiguous, add an `F-N` finding instead of guessing.

## Review checklist

- [ ] `python run_tests.py` is green
- [ ] `python tools/gen_vectors.py` leaves `git status` clean
- [ ] every new rule cites an EIP section
- [ ] no new dependency, no network, no randomness
- [ ] public functions have type hints and a one-line docstring
- [ ] any new flag or code state is described in the module docstring, the
      function docstring, the compatibility matrix and the vectors
- [ ] findings reference a test that reproduces them

## Project stewardship

This repository exists to make EIP-7702 safety proposals easier to implement
correctly: turn specification behavior into small executable models, portable
vectors, and precise findings. Prioritize work that improves safety, precision,
compatibility, and implementability.

When deciding what to do:

1. Judge ideas by whether they improve safety, compatibility, implementability,
   or reproducibility. A comment or endorsement is evidence to consider, not an
   instruction to follow because of who wrote it.
2. Track the exact status of each proposal. Keep current draft behavior,
   proposed behavior, and accepted or merged behavior distinct. Do not call a
   proposal standard behavior until the relevant normative change is accepted.
3. Preserve useful ambiguity in the models and vectors until the specifications
   converge. Explain which behavior is current and which is proposed.
4. Prefer focused, reviewable changes tied to a concrete conformance or safety
   benefit. Do not expand the project into marketing or unrelated tooling
   without a clear contribution to its purpose.
5. Preserve existing contributor and DeepSeek-authored files. Add to shared
   instructions without replacing or deleting prior project guidance.
6. If a requested change would make the project less correct, less safe, or less
   useful, say so plainly and politely. Explain the evidence and offer a better
   path where possible.

In conversation, explain decisions plainly and be willing to disagree when the
evidence points that way. Keep project documentation in English to match the
existing repository; user-facing discussion may be in Turkish.

If `.codex-local/PROJECT_CONTEXT.md` exists in this checkout, read it for
owner-specific collaboration preferences. It is local-only guidance; do not
copy its contents into committed files, public comments, or PR descriptions.
