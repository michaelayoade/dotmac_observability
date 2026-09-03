# ADR-0011: The telemetry ingestion contract, and the audit projection that is never the evidence

- **Status:** Accepted
- **Date:** 2026-09-03
- **Related:** ADR-0008 (the observability bundle), ADR-0009 (one fleet agent),
  ADR-0004 (public logical, private resolved), `AGENTS.md` rules 33 to 36
- **Owns:** `contracts/telemetry-ingestion.schema.json`,
  `inventory/ingestion.toml`, `src/dotmac_observability/ingestion.py`,
  `prometheus/rules/01-ingestion-meta.yml`

## Context

The fleet ships telemetry through one agent (ADR-0009) into stores this
repository configures (ADR-0008). Between the two there was no contract. What
arrives was whatever the sender happened to emit, and what is accepted was
whatever the store happened not to reject — which is not a boundary, it is the
absence of one, and it has three consequences that only look different.

**Nothing owned the accepted vocabulary.** An open field set at ingestion is
how a log store acquires an index dimension with a million values, and how a
header nobody meant to ship becomes permanently searchable. A store cannot
un-receive a credential.

**Nothing distinguished "no drops" from "no data".** A drop counter reading
zero because nothing was shipped and one reading zero because nothing was lost
are the same number and opposite news. This is the same defect class the
Observer census found twice already: eighteen targets reporting `up == 1` while
1.86 million samples were refused at append, and a `rule inactive` state that a
deleted rule, a failed evaluation and a vanished target all produce.

**Nothing said which surface was evidence.** Audit and telemetry were being
discussed as one pipeline. They are not the same kind of thing, and treating
them as one is how a searchable copy quietly becomes the record.

## Decision

### One versioned contract for what is accepted

`observability-telemetry-ingestion.v1` declares the resource identity every
record carries, the accepted attribute vocabulary and what each attribute is
validated against, which attributes may become stream labels, what is refused,
and how each stream's arrival, integrity and lag are measured. It is a public
logical document like every other input (ADR-0004): no address, no store path,
no credential basename.

The kernel decides what to EMIT and this decides what is ACCEPTED. They are
deliberately two documents in two repositories, because a wire contract only
one end can read is a convention, and a convention is what a framework default
change quietly overrides.

**A field accepted and never validated is a field nobody owns.** Every accepted
attribute declares an `enum`, a named `shape`, or `opaque` with a rationale a
reviewer can disagree with. `opaque` is available and is not free.

### Rejection carries its own planted proof, and the negative suite has a positive control

Each rejection rule names synthetic material that MUST be refused, and the
loader RUNS the classifier over that material as a gate — so a rule that has
stopped biting fails `make check` in the run that broke it rather than in an
incident. The gate compares the rule NAME rather than the outcome, because a
planted probe usually carries a field the contract does not accept anyway: a
classifier checking the vocabulary first would refuse every probe for the wrong
reason while every rejection rule sat inert, and every assertion would still
pass.

The document also carries `accepted_control` records that must be ACCEPTED.
This is not symmetry for its own sake. A classifier that refuses everything
satisfies every rejection probe ever written and looks, from the negative
suite, like a boundary working perfectly; only the control can tell the two
apart. It earned its place immediately — the first draft refused an ordinary
request log line, because a UUID is thirty-six characters of hex and dashes and
matches an opaque-token heuristic exactly. The repair is that a value-shape
rule does not apply to an accepted attribute whose declared validation is a
strict structural shape and whose value satisfies it. Name and prefix rules are
not exempted: a forbidden field is forbidden however tidy its contents are.

Planted material is BUILT rather than committed. Nothing in the contract or the
classifier is a string that looks like a credential; the shapes are assembled
from repeated characters at call time. A repository that had to commit
realistic secret-shaped strings in order to prove it refuses them would be
adding itself to its own scanner's exclusion list to do it, and this one has
published a credential basename once already.

### Arrival, integrity and lag are three facts, and unmeasured is a fourth

Every stream declares a separate arrival counter and integrity counter, and the
renderer emits four rules per stream from them:

| Rendered alert | Says |
| --- | --- |
| `<Signal>ShipperSilent` | nothing has arrived for the declared budget |
| `<Signal>IntegrityUnmeasured` | the drop counter has never been observed |
| `<Signal>IngestionDropping` | records arrived and were not stored |
| `<Signal>IngestionLag` | the store is behind by more than the budget |

Silence is written with `absent_over_time` and never as a rate threshold. The
two read like the same question and are not: when a shipper stops, its series
stops existing, and a comparison against a series that does not exist matches
no rows and produces no alert at all. Absence is the one query shape that
survives the thing it watches going away, which is why a metrics pipeline is
worst at noticing exactly this.

The drop alert is delta-shaped over the declared window (`AGENTS.md` rule 30).
The unmeasured alert exists because the alternative is that a dead pipeline and
a clean one share a dashboard panel.

**A stream whose lag nothing measures renders no lag alert** and declares
`lag_unmeasured` with a rationale and an owner instead. The easy alternative
was naming a plausible metric; that renders a rule that can never fire, which
reads on every dashboard exactly like one quietly passing — `AGENTS.md` rule 8
by another route. The same reasoning makes a `planned` projection render no lag
alert.

### A deadman that has never fired is not known to work

Each deadman declares its planted condition, where the procedure is written,
and the date it was last observed to fire — or the literal `never`. `never` is
counted by a two-directional ratchet and stamped into the rendered alert's own
annotations, so an operator reading it during an incident learns that nobody
has watched it work. A deadman that has never fired is indistinguishable from
one whose expression matches no series at all, and the moment that matters is
the moment somebody is relying on it.

**Both deadmen ship unproved, and the limit is stated rather than discovered.**
Neither can detect the evaluator being dead, because the evaluator is what
evaluates them. That case needs a watcher outside this host. The alternative —
an always-firing heartbeat routed to a dead-man's-switch service — was
considered and refused: there is no such receiver in `routing/`, so the rule
would page continuously and be silenced within a week, which is worse than the
gap it was meant to close. It is recorded in `docs/CONTROL_EXCEPTIONS.md`.

### Audit is evidence; telemetry is observation; the projection is neither

A product writes its authoritative audit row in the same transaction as the
decision it records, into its own database. That row is the evidence. Logs,
metrics and traces are operational observations. A central audit projection may
exist so the fleet can be searched, and it is never authoritative:
`authoritative` is a `const false` in the contract, so no document can express
the other value — a projection that CAN be declared authoritative eventually
is, usually in the hour when the application database is the thing that is
down.

Three properties follow, and each is gated:

- **Its retention is bounded from above by its source's.** A projection
  retained longer than the rows it derives from becomes, on the day the source
  ages one out, the last copy of that row — and a last copy is authoritative
  whatever any document says.
- **It cannot claim a rebuild that never ran.** `last_rebuilt: never` admits
  only the verdict `UNMEASURED`, and the ratchet runs the other way too: a
  recorded rebuild still reading `UNMEASURED` is refused, so a completed proof
  is recorded rather than left looking outstanding.
- **The lag alert says it is not authoritative, and names what is.** The
  natural response to `projection is behind` is to trust the projection less,
  and the correct response is that nothing about what is true has changed —
  only what fleet search can currently find. An operator told a surface is not
  authoritative and not told what is goes looking, and what they find will be
  another projection.

`compare_rebuild` implements the rebuild-and-compare path today, against row
digests rather than counts: two sets of equal size agree on every count anybody
would think to check. Two empty sides, or a side that could not be read, report
`UNMEASURED` rather than agreement — a comparison that cannot fail is not a
comparison, the same refusal the live-observation contract makes about an empty
tree read-back.

**Which half exists.** The comparison is complete and exercised. Its two
readers are not: producing the source side means reading audit rows out of each
application's own database, which is that application's boundary and not this
repository's, and producing the projection side means reading back a projection
that is not deployed. The contract therefore ships `status = "planned"` and
`verdict = "UNMEASURED"`, and neither can be quietly improved — the gate
refuses both alternatives.

## Consequences

`inventory/ingestion.toml` joins `inventory/bundle.toml` as a required input,
so a control plane cannot be loaded without declaring what it accepts. Log
retention is now one decision compared across two documents; the label budget
is rendered into Loki's own `max_label_names_per_series`, so the number a
reviewer reads and the number the store enforces are one number.

One scrape job is added. Alertmanager was rostered by the bundle and scraped by
nothing, so no `alertmanager_*` series existed and the notification-path
deadman would have been permanently silent. Grafana and promtail remain
unscraped and are recorded as gaps rather than fixed, because adding a job
whose series nothing reads is the other half of the same mistake. Loki was
already scraped, under `fleet-infrastructure` — the duplicate-job gate found
that when this change first tried to declare it a second time, which is a
better outcome than the measurement that prompted it.

**What this does not do.** Nothing applies the classifier to bytes on the wire.
The policy is complete, gated and proved against planted material; the runtime
stage that enforces it at the ingestion edge is not deployed, and that is
`AGENTS.md` rule 33's unmonitored half. Describing the rejection as enforced in
production would be exactly the overclaim rule 29 exists to prevent.

## Alternatives considered

**Scrub forbidden material and accept the record.** Rejected: a scrubber that
misses one field has accepted it, and there is no second chance with a log
store. Refusal is attributable to a sender and produces a fixable defect
report; a silent scrub produces a habit.

**Regular expressions in the contract document.** Rejected: a pattern in a data
file is code that no reviewer reads as code, and two documents spelling `uuid`
differently is the drift this contract exists to remove. Shapes are named and
the names are implemented once.

**A metrics manifest per product, as rule 8 describes.** Deferred, not
rejected. The producer proof for every alert expression in this repository is
still `none yet (PR 3C)`, and the alerts added here inherit that exception
rather than inventing a narrower half-gate that would look like coverage.
