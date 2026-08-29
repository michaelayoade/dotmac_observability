# ADR-0001: The observability control plane has one Git owner

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Related:** `docs/adr/0002-deterministic-rendering-and-immutable-releases.md`,
  `AGENTS.md` rules 2, 5 and 17

## Context

The Dotmac Observer host runs the fleet's observability stack from
`/opt/observability`: Prometheus, Alertmanager, Grafana and Loki. The
Prometheus and Alertmanager configuration that stack loads had no
version-controlled owner at all.

Concretely, `prometheus.yml` and `alerts.yml` were single-file bind mounts,
edited in place on the host. A single-file bind mount is bound to an inode, so
any editor that writes a replacement file (`sed -i`, `mv`, most editors' save)
detaches the mount: the container keeps reading the old inode and the edit
appears to succeed while changing nothing until somebody recreates the
container. The gesture that survives this is `cat >>`, appending to the
existing file. That is how the host came to be maintained: append-only, by
hand, at a shell prompt.

An edit path with those properties has no reviewer, no attribution, no history,
no atomicity and no way to fail. There is nowhere to put a gate, because there
is no event to gate. The observable result is the state the fleet is in now:
central Prometheus scrapes ERP, ERP publishes rendered alert rules, and the
central evaluator loads none of them. Nothing reports the disagreement, because
reporting a disagreement requires two descriptions of intended state and only
one exists.

Two further problems compound it. Notification credentials live on the host as
whatever string was pasted into the configuration, so rotating one is an
archaeology exercise. And there is no artifact that says what the last known
good configuration was, so "roll back" has no target.

## Decision

The Observer control-plane configuration gets exactly one version-controlled
owner: this repository, `dotmac_observability`.

It owns the evaluator and router for each environment: which product bundles
are accepted (digest-pinned), what is scraped and federated, how Prometheus and
Alertmanager are configured, who is paged and under what routing and
inhibition, and how a release reaches the host and is verified or rolled back.

Product repositories keep their own rule content. A product owns its metric
definitions, its exporter, its domain alert decisions and its rule bundle as a
published artifact. This repository pins an immutable bundle by digest,
assembles it into a release, and decides where it is loaded and who is paged.
It does not author a product alert expression and does not edit a fetched
bundle. If a rule is wrong, the product publishes a new bundle and the pin
moves.

Reusable rendering, conformance and promotion mechanics belong to
`dotmac-deployment-foundation` in `dotmac_starter_mt`, not here. Secret values
belong to OpenBao. Cross-repository engineering standards belong to
`dotmac_governance`.

Consequently `/opt/observability` stops being an editing surface
(`AGENTS.md` rule 2). Every live byte is rendered here, staged as an immutable
release directory and activated atomically. A change made on the host is drift
to be reported and reverted, not a fix to be kept.

## Consequences

**A configuration change becomes a reviewable diff.** A routing change arrives
as a diff of the actual Alertmanager configuration, because the rendered bytes
are committed (ADR-0002). A reviewer does not have to simulate the renderer in
their head.

**Whole classes of failure become expressible as gates.** A route to a receiver
nobody declared, a severity class that reaches nothing, two products claiming
one job name, a federation that does not rename its imported `up` series, an
expectation of more up targets than there are declared endpoints: each of these
is now a document-level fact that `validate.semantic_findings` can refuse. None
of them was checkable when the configuration was a file on a host.

**Rollback acquires a target.** An immutable release directory and a preserved
previous pointer make "restore the exact preceding release" a mechanical act
rather than a reconstruction.

**Credentials become references.** A credential is an OpenBao path and a
logical file name in the inventory, and a `*_file` path in the rendered
configuration. Rotation becomes a deployment act against a known set of names.

**A product's alert change now crosses a repository boundary.** This is the
main cost, and it is deliberate. Changing an ERP threshold means a change in
`dotmac_erp`, a published bundle, and a pin bump here. That is slower than
editing a file on the Observer host, and it is the point: the slow path is
reviewed by the people who own the metric and recorded where the fleet can see
it.

**This repository becomes a promotion path to a production host,** and
therefore inherits the obligations that come with one: an exact protected-`main`
SHA as the promotion target, a human-named target host, a rehearsal on a
disposable host first, and a receipt for every attempt including the failed
ones.

**The boundary must be actively defended.** Owning the evaluator makes it
one line's work to "just fix" a product's threshold centrally, at which point
the product's own tests prove something the fleet no longer runs. `AGENTS.md`
§"The line this repository must not cross" states the prohibition; the only
alert expressions this repository may own are its own control-plane
meta-alerts (deadman, evaluator health, bundle-digest mismatch), because no
product can observe those. Enforcement of the no-authorship rule is not yet
written (`AGENTS.md` rule 5, PR 3).

## Alternatives considered

### (a) Keep editing the host in place

Rejected. This is the status quo and it produced the defect. The edit path
cannot be reviewed, cannot be attributed, cannot be rolled back and cannot
fail. Adding process discipline on top ("always update the wiki after
editing") does not change any of those properties; it adds a second artifact
that drifts from the first. The inode behaviour of single-file bind mounts also
means the safe-looking edits are the ones that silently do nothing, so
discipline pushes operators towards `cat >>` and away from anything
structured.

### (b) Let each product repository deploy its own rules directly to Observer

Rejected, and it is the most tempting alternative because it looks like correct
ownership: the product owns the rule, so let the product ship it.

The problem is that the Observer host is shared and the products are
independently released. Every product would need write access to one host's
configuration directory, so the blast radius of any product's deployment bug is
the fleet's entire alerting. Nothing would arbitrate collisions: two products
can both define `WorkerStalled`, or disagree about what values `severity` may
take, and the second deployment silently wins. Prometheus loads rule files as a
set, so a syntactically invalid file from one product degrades evaluation for
all of them. There would be no single answer to "what is the evaluator
supposed to be running", so no drift detection and no rollback target.

The accepted split keeps what is right about this option — the product owns the
rule content and publishes it — and adds one arbiter that decides which
immutable version is accepted and loaded. `AGENTS.md` rule 6 exists precisely
to catch the collisions this alternative cannot see.

### (c) Put the control plane inside `dotmac_starter_mt`, beside `dotmac-deployment-foundation`

Rejected. It conflates a reusable mechanism with one deployment's state.

`dotmac-deployment-foundation` is a stateless facility: a product declares
input, the facility renders and promotes, and the facility contains no
product's data. The Observer control plane is the opposite: it is the accepted
pins, the real scrape inventory and the routing policy for one specific set of
hosts. Storing that inside a package that every product composes would put one
deployment's state into every consumer's dependency tree, and would make
"change who gets paged" a release of shared infrastructure code.

It would also invert the release relationship. Routing changes weekly; the
rendering facility should change rarely and be pinned by its consumers. Sharing
one repository forces the two cadences together and pressures the facility to
grow branches for this deployment's specifics.

The boundary is therefore: the foundation owns reusable mechanics and gets the
promotion facility in PR 6; this repository owns the accepted state and calls
it.

### (d) Create the owner, but let it also own alert expressions centrally

Rejected, and this is the alternative most likely to be re-proposed, because
the first time a product's threshold is wrong at three in the morning it will
look obviously correct.

Central authorship separates the alert from the metric. The person who knows
what `dotmac_erp_worker_queue_depth` means, what it does under a backlog, and
what value is actually bad, is in the product repository, along with the tests
that pin that behaviour. Writing the expression here means the product's test
suite proves a threshold the fleet does not run, and the product's next release
either reverts the central edit or diverges from it invisibly.

It also destroys the bundle's identity. A locally patched bundle makes one
version string name two different contracts, and every digest recorded in a
receipt stops identifying what actually ran.

The retained exception is narrow and justified by the same reasoning:
control-plane meta-alerts (deadman, evaluator health, bundle-digest mismatch)
are authored here because they are about this repository's own machinery, and
no product is in a position to observe them.
