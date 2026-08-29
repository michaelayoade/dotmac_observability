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
governance, the seven contracts, the typed model, four-layer validation, the
deterministic renderer, the resolution layer and both scanners exist. The
production inventory, bundle fetching, live verification, promotion, receipts
and drift comparison do not.

## Commands

`make help` lists every target. `make check` is everything CI runs.
