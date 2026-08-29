# inventory/

The scrape and federation inventory for one control plane: what Prometheus
watches, and which upstream Prometheus servers it imports from.

- `control-plane.toml` — the environment, its LOGICAL host, both evaluator
  images (pinned by digest) and loopback listen addresses, `release_root`,
  `secrets_dir`, external labels, the global intervals and the optional
  `[smtp]` block. Governed by `contracts/control-plane.schema.json`.
- `targets/*.toml` — one file per product, `kind = "targets"`, declaring that
  product's scrape jobs. Governed by `contracts/target.schema.json`.
- `federations/*.toml` — one file per imported upstream, `kind = "federation"`,
  each with a mandatory `rename_prefix`. Same contract, other branch.

Files are discovered by a `sorted()` glob, so ordering is stable across
machines; `kind` is checked rather than inferred from the directory.

## Logical, not resolved

Every document here describes what is scraped, by whom, over which protocol
and with what expectations. **None of them says where anything is** (ADR-0004,
ADR-0006). A job carries a `target_id` and a boolean `authenticated`; the
endpoint it resolves to and the credential it presents come from the private
ObserverInventoryV1 document at promotion time.

That is a completeness statement rather than a restriction: these documents are
complete as a description and deliberately incomplete as a deployment. There is
no field an endpoint can be typed into except a `publication` block, which also
requires a rationale, a named approver and a date — so the per-target exception
cannot be taken by omission.

**Populated by PR 3C**, from PR 2's read-only census. The reference fixture at
`tests/fixtures/reference/inventory/` shows the shape and is not production:
its digests are placeholders and its one published endpoint is `.invalid`.

**Trap:** `expected` on a scrape job is the number of targets that must report
up, and it is not decoration. A job that resolves to zero targets emits no
series and no failures, which every alert written over it reads as a healthy
system. Setting `expected` higher than the RESOLVED endpoint count is refused
(`TARGET-UNREACHABLE-EXPECTATION`, at the resolution layer since the public
document no longer knows the count); omitting it buys silence.
