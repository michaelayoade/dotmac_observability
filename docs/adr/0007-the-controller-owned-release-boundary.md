# ADR-0007: The controller-owned release boundary

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Related:** `docs/inventories/observer-as-built.md` OBS-01, OBS-02, OBS-03,
  OBS-08, OBS-20, OBS-21; `docs/adr/0002-deterministic-rendering-and-immutable-releases.md`,
  `docs/adr/0006-the-private-inventory-and-what-this-repository-does-not-own.md`

## Context

PR #7 recorded a hand edit made to the Observer host on 2026-08-29 and, in
doing so, surfaced a finding the census had missed entirely. The change removed
a retired product's scrape job and alert group — both inside the scope this
repository was designing for — and then had to go on and edit **Grafana
dashboard JSON and a Grafana template variable**, which nothing here owns,
reviews, renders or would ever notice.

That was recorded as OBS-20: Grafana provisioning and the Loki/promtail
configuration are a second unversioned edit surface with exactly the properties
OBS-01 describes. OBS-21 is a worked example of the same gap — promtail still
stamps a decommissioned host's label on a surviving workload's logs, and no
gate reads that file.

Two ways of responding were available, and only one of them is honest.

The first is to keep the scope at Prometheus and Alertmanager and narrow the
claim to match: *this repository explains the evaluator and the router.* That
is truthful, and it leaves the stack with two edit surfaces where the whole
point was to have none. The operator's experience would be unchanged, because
an operator does not think in terms of which config file has an owner.

The second is to widen the scope to what the controller actually owns. That is
more work and it is the one that closes the finding rather than documenting it.

## Decision

**The first adopter brings ALL controller-owned deployment configuration under
one release boundary.**

Inside the boundary, and therefore inside one authorized release digest:

- Prometheus configuration and rule loading
- Alertmanager routing, inhibition, receivers and templates
- **Grafana provisioning and dashboards**
- Loki configuration
- promtail and any other collector configuration
- exact container image digests for every service in the stack
- the promotion receipt and the drift check over all of the above

Explicitly **outside** the boundary, and not this repository's business:

- tenant data
- domain decisions
- databases and their contents
- logs and metrics themselves — the observations, as against the configuration
  that collects them
- ordinary product settings

### The claim this repository is allowed to make

The formulation the delivery plan has been using is **too broad and is
withdrawn**:

> ~~Every running byte explained by release digest + private inventory digest +
> secret-reference set + deployment authorization = rendered runtime digest.~~

"Every running byte" is not a claim anybody can honour. A running host has
kernel bytes, package bytes, tenant data and log data, and none of it is
deployment configuration. A promise that broad is either false or so heavily
qualified in the reader's head that it stops meaning anything.

The claim is:

> **Every controller-owned image and deployment-relevant configuration byte is
> explained by an authorized digest.**

Narrower, and unlike its predecessor it is checkable. "Controller-owned"
enumerates to the list above; "deployment-relevant" excludes the data planes;
"an authorized digest" points at an approved plan issued by
`dotmac-deployment-control` (ADR-0006 §7), not at something this repository
attests to itself.

### Why one boundary rather than several

A release boundary that covers four of six services is not a smaller version of
the property — it is the absence of it. The failure this repository exists to
remove is an operator making a correct, careful change that no gate can refuse
and no receipt records. That failure is available through *any* uncovered
surface, so a partial boundary leaves the original defect intact while
producing evidence that looks like coverage.

The 2026-08-29 CRM removal is the proof, and it is worth being precise about
why. The parts of it inside the current scope were *anticipated*: the
provenance ledger had prepared an exact eleven-item deletion list, and the
operator executed it. The parts outside the scope were not on any list, were
found by looking, and would have been left behind by a promotion that thought
it had reproduced the host. A release boundary that a careful operator has to
step outside of, in the very first change after it is designed, is drawn in the
wrong place.

### What this does not decide

**How** each surface is rendered. Grafana dashboards are JSON produced by a UI
and are not obviously deterministic under round-tripping; Loki and promtail
have their own config shapes. Bringing them inside the boundary is this
decision; the rendering strategy for each is a separate design with its own
evidence, and pretending otherwise here would be the same overreach ADR-0006
had to correct.

**When.** This is scope, not a schedule. The delivery train orders the work,
and each surface arrives with its own contract, fixture, committed render and
conformance evidence, in the same shape Prometheus and Alertmanager already
have.

## Consequences

- The delivery train grows: Grafana, Loki and collector configuration each need
  a contract, a fixture and a rendering path before a production promotion can
  claim the boundary.
- The census's OBS-20 stops being an open finding and becomes accepted scope.
  OBS-21 becomes a defect *inside* the boundary rather than a curiosity outside
  it, which is what makes it fixable through the promotion path instead of by
  hand.
- Conformance gets harder in a useful way: `docker compose config`, promtool
  and amtool cover two of the six surfaces, so the remaining four need their
  own acceptance oracles rather than inheriting an existing one.
- Every claim in `README.md`, `docs/ARCHITECTURE.md` and `docs/SECURITY.md`
  that used the "every running byte" formulation is corrected to the narrower
  one in the same change that accepts this decision. A withdrawn claim left
  standing anywhere is worse than never having narrowed it.

## Alternatives considered

**Keep the scope and narrow the claim.** Rejected above: truthful, and it
leaves the defect in place while producing evidence that reads like coverage.

**Widen the claim instead of the scope** — keep saying "every running byte" and
treat the uncovered surfaces as a known gap. Rejected outright. That is the
overclaim `AGENTS.md` rule 15 exists to prevent, and it is exactly how a
control exception becomes a grandfathered breach.

**Give Grafana its own owner.** Rejected for now, though it is the alternative
with a real argument behind it: dashboards are edited by many people for
product reasons, which is not the change profile the promotion lane is built
for. But dashboard *provisioning* — which dashboards exist, from which source,
in which org — is deployment configuration by any reading, and splitting
provisioning from content across two owners would put the boundary in a place
neither owner could describe. If dashboard content later needs its own lifecycle
it can get one, inside a provisioning boundary this repository still owns.
