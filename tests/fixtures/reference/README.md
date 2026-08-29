# reference fixture

A complete, realistic control plane that exercises every rendering path: a
plain scrape job, an authenticated one, per-job overrides, a deliberately
published target with a non-default metrics path, a federation with its
mandatory rename, a delivering receiver, a reviewed null receiver, both
severity routes, and an inhibition.

It is **not** the production inventory, and under ADR-0004 it never becomes
one. The digests are placeholders and every host is an `.invalid` name — not as
a placeholder awaiting real values, but because there are no real values to put
here: production resolution lives in a private inventory and reaches a render
only at promotion time.

## Two halves, like production

- `inventory/` and `routing/` are the PUBLIC half: logical target IDs,
  capabilities, protocol, policy. Complete as a description, deliberately
  incomplete as a deployment.
- `private/inventory.json` is a synthetic instance of the PRIVATE half. It is
  tracked, which is the one place this fixture departs from production shape,
  and it is safe for reasons a test checks rather than a reader trusts — see
  `private/README.md`.

Together they render. Either alone does not, which is the property CI needs to
exercise: `make render-check` is the only place the join is proved end to end
against committed bytes.

`rendered/` holds those bytes. It is the sensitivity proof for AGENTS.md rule
13: without a committed expectation, a determinism test only proves the
renderer agrees with itself, which it would do even while emitting the wrong
thing.

## Why the fixture carries no copy of the contracts

Deliberate, and it is why the CLI has a `--contracts` flag. A fixture carrying
its own copy of the schemas would prove the copy, and the two would drift the
first time a contract changed. So the fixture is loaded with
`--root tests/fixtures/reference --contracts contracts` and validated against
the real ones.
