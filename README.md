# dotmac_observability

The Git owner of the Dotmac observability **control plane**: the evaluator and
router that load product alert bundles, scrape product targets, and deliver
notifications.

It exists because that configuration previously had no owner. Observer's
`prometheus.yml`, `alerts.yml` and `alertmanager.yml` lived only as single-file
bind mounts under `/opt/observability`, edited in place on the host. An
unreviewable, unattributable, non-atomic edit path cannot fail a promotion
gate — which is how central Prometheus came to scrape ERP while loading none of
its rendered alert rules.

## What this repository owns

- Observer target and federation inventory
- Accepted product alert-bundle pins (digest-locked)
- Prometheus scrape and rule-loading configuration
- Alertmanager routes, inhibition, receiver policy and templates
- Deterministic configuration rendering and validation
- Promotion, reload verification, rollback and drift detection
- Deadman and delivery canaries, each carrying the planted condition that
  proves it fires — or the record that nobody has yet watched it
- The telemetry ingestion contract: what the fleet shipper may put into this
  control plane, what is refused, and how arrival, integrity, silence and lag
  are told apart (ADR-0011)
- Telemetry retention and access, and the audit projection's retention — which
  is bounded from above by the application rows it derives from, because a
  projection is never the evidence
- Deployment receipts and operational runbooks

## What it does NOT own

| Owner | Responsibility |
| --- | --- |
| Product / module | Metric definitions and domain alert decisions |
| Product assembly | Metrics exporter and the product's own rule bundle |
| `dotmac-deployment-foundation` | Reusable rendering, conformance and promotion mechanics |
| **dotmac_observability** | Accepted bundle pins, scrape inventory, evaluator config, routing, deployment |
| OpenBao | Secret values |
| `dotmac_governance` | Cross-repository standards |

A rule about ERP's behaviour belongs to ERP. This repository decides only
*which* immutable bundle is loaded, *where* it is loaded, and *who* is paged.

## Shape

Typed inventory (`inventory/`, `bundles/`, `routing/`) describes the control
plane **logically** — what is scraped, by whom, over what protocol, with which
policy — and says nothing about where anything is. The resolution arrives
separately, at promotion time, as a private `ObserverInventoryV1` document
whose version and digest are the only parts that ever appear in public
(ADR-0004, ADR-0006).

The two together render deterministically. `make render-check` is a byte
comparison against the committed reference render, so a reviewer sees a routing
change as a diff of the actual Alertmanager configuration rather than of the
TOML that implies it. A **production** render is not committed and cannot be:
its bytes legitimately carry resolved endpoints, so it is produced at promotion
time and recorded by digest.

A deployment is then authorized as one binding — release, inventory, render and
images together, in a frozen plan approved before anything runs. Any three of
those agreeing proves nothing about the fourth, which is why they are bound
rather than checked one at a time. That binding belongs to
`dotmac-deployment-control`; this repository is its first adopter, consumes an
approved plan and defines no approval semantics of its own.

The claim it makes is deliberately narrow: **every controller-owned image and
deployment-relevant configuration byte explained by an authorized digest**
(ADR-0007). Tenant data, domain decisions, databases, logs, metrics and
ordinary product settings are out of scope.

Promotion is a state machine — `FETCHED → VALIDATED → REHEARSED → STAGED →
RELOADED → VERIFIED → ACCEPTED` — that rolls back to the exact preceding
release on any failure before acceptance, and publishes a non-secret receipt.

## Status

This repository is being built in a reviewed train. See
`docs/ARCHITECTURE.md` § "Delivery train" for what exists today and
`docs/CONTROL_EXCEPTIONS.md` for every region that is declared unmonitored
rather than silently exempt — read that file before describing any rule here
as enforced.

**Nothing is promoted, and no production configuration is committed.** The
governance, the contracts, the typed model, four-layer validation, the
deterministic renderer, the resolution layer, both scanners and the production
inventory exist. So, now, does the promotion lane: the state machine
(`promote.py`), the six-condition read-back verifier (`live_verify.py`), the
receipt writer and its refusals (`receipt.py`), and the three-way drift
comparison (`drift.py`).

It still cannot promote anything, and the reason is a boundary rather than a
gap in the work. Every host effect — staging an immutable release directory,
capturing the previous pointer, transporting the tree, reloading the
evaluators, reading them back and restoring on failure — is a method on
`promote.PromotionFacility`, a Protocol this repository declares and
`dotmac-deployment-foundation` implements. No version providing them is
installable, so `.github/workflows/promote.yml` stops at the step that probes
for one. `docs/adr/0010-the-promotion-executor-and-the-facility-contract.md`
states what it must provide.

ADR-0011 adds the ingestion boundary: the contract
(`contracts/telemetry-ingestion.schema.json`), the classifier that decides one
record and says WHICH rule refused it (`ingestion.py`), the gates that run that
classifier over planted material as part of `make check`, and the rendered
ingestion alerts. Its policy is enforced; the runtime stage that would apply it
to bytes on the wire is not deployed, and that half is recorded as unmonitored
rather than described as working.

The audit projection is declared and does not exist. `compare_rebuild` is the
rebuild-and-compare path and is complete; both of its readers — application
audit rows on one side, a deployed projection on the other — are not, so the
contract carries `status = "planned"` and `verdict = "UNMEASURED"` and refuses
any more optimistic value.

Bundle fetching (`bundle.py`) also does not exist.

## Commands

`make help` lists every target. `make check` is everything CI runs.
