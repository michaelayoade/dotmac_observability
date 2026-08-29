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
- Deadman and delivery canaries
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

Typed inventory (`inventory/`, `bundles/`, `routing/`) is rendered
deterministically into `deploy/rendered/`, which is **committed**. `make
render-check` is a byte comparison: if the inputs and the committed bytes
disagree, CI fails. A reviewer therefore sees a routing change as a diff of the
actual Alertmanager configuration, and an air-gapped operator gets working
configuration from a checkout.

Promotion is a state machine — `FETCHED → VALIDATED → REHEARSED → STAGED →
RELOADED → VERIFIED → ACCEPTED` — that rolls back to the exact preceding
release on any failure before acceptance, and publishes a non-secret receipt.

## Status

This repository is being built in a reviewed train. See
`docs/ARCHITECTURE.md` § "Delivery train" for what exists today and
`docs/CONTROL_EXCEPTIONS.md` for every region that is declared unmonitored
rather than silently exempt.

**PR 1 (this change) ships governance, contracts and the deterministic
rendering mechanics. It contains no production configuration and promotes
nothing.**

## Commands

`make help` lists every target. `make check` is everything CI runs.
