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
requires a rationale — so the per-target exception cannot be taken by omission.
The block carries no approver, deliberately: the approval is the protected-branch
merge that accepted the rationale, and a name in the file would be self-attested
(ADR-0006 §4).

**Populated** for `production` on 2026-08-30, derived from the live host
rather than composed by hand: intervals, metrics paths, schemes, target counts,
authentication flags, image digests and evaluator versions were all measured.
The reference fixture at `tests/fixtures/reference/inventory/` shows the shape
and is not production: its digests are placeholders and its one published
endpoint is `.invalid`.

Fifteen logical targets are declared here (fourteen scrape jobs plus one
federation), against the sixteen the private document holds. The one it does
not declare is the retired CRM entry, which is what the pending supersession
retires — see `docs/inventories/observer-as-built.md` §15, and note that the
supersession is **blocked** on a prior migration of the stored document.

**`validate` cannot yet run to completion over this tree.** The loader requires
the three `routing/` documents, which are PR 3's scope and are still absent, so
a full cross-document and resolution pass refuses at load. Each document here
has been validated against its own contract, and the public/private vocabulary
reconciles in both directions, but that is not the same as the composed gate
having run.

**Trap:** `expected` on a scrape job is the number of targets that must report
up, and it is not decoration. A job that resolves to zero targets emits no
series and no failures, which every alert written over it reads as a healthy
system. Setting `expected` higher than the RESOLVED endpoint count is refused
(`TARGET-UNREACHABLE-EXPECTATION`, at the resolution layer since the public
document no longer knows the count); omitting it buys silence.
