# Contributing

Thanks for looking. This repo is small on purpose.

## Before you start

Read [`AGENTS.md`](AGENTS.md). It applies to humans too: standard library only,
`unittest`, reproducible vectors, and one finding per ambiguity.

## The two useful contributions

1. **A new conformance vector.** Find a behaviour the current suite misses,
   add it to `tools/gen_vectors.py`, regenerate, and explain which spec
   sentence it pins down.
2. **A finding.** If two implementations can disagree, that is worth more than
   a feature. File it in `docs/02-findings.md` with the quote and a test.

## Pull requests

- keep the diff small and focused
- `python run_tests.py` must be green
- `python tools/gen_vectors.py` must leave the worktree clean
- no new dependencies

## Commit messages

Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`. The subject
is imperative and under 72 characters.
