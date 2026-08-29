# inventory/

The scrape and federation inventory for one control plane: what Prometheus
watches, and which upstream Prometheus servers it imports from.

- `control-plane.toml` — the environment, its host, both evaluator images
  (pinned by digest) and listen addresses, `release_root`, `secrets_dir`,
  external labels, the global intervals and the optional `[smtp]` block.
  Governed by `contracts/control-plane.schema.json`.
- `targets/*.toml` — one file per product, `kind = "targets"`, declaring that
  product's scrape jobs. Governed by `contracts/target.schema.json`.
- `federations/*.toml` — one file per imported upstream, `kind = "federation"`,
  each with a mandatory `rename_prefix`. Same contract, other branch.

Files are discovered by a `sorted()` glob, so ordering is stable across
machines; `kind` is checked rather than inferred from the directory.

**Populated by PR 3**, from PR 2's read-only census. The reference fixture at
`tests/fixtures/reference/inventory/` shows the shape and is not production:
its hosts are `.invalid` and its digests are placeholders.

**Trap:** `expected` on a scrape job is the number of targets that must report
up, and it is not decoration. A job that resolves to zero targets emits no
series and no failures, which every alert written over it reads as a healthy
system. Setting `expected` higher than the number of declared endpoints is
refused (`TARGET-UNREACHABLE-EXPECTATION`); omitting it buys silence.
