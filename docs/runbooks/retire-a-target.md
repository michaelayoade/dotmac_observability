# Retiring a scrape target

How a decommissioned product leaves the control plane without leaving orphans
behind, and how the private inventory is moved to a new version safely.

Owed by `docs/runbooks/README.md`. It lands with the capability it describes
and not before, per that file's rule. **No step touches the Observer host**;
the host-side removal is assumed to have already happened and been recorded as
adoption evidence.

**You do not run the supersession by hand.** A hand-run one is exactly the
unversioned, unreproducible edit this programme replaces, so the write is
performed by `.github/workflows/private-inventory-supersede.yml`, from
protected `main`, applying a request that was reviewed and merged. Your job is
to author that request and get it approved; the workflow does the rest and is
the only writer.

## When this applies

A product is provably gone — not being wound down, gone — and its scrape job,
its rules and its credential are still described here.

"Provably" is doing work in that sentence. `docs/inventories/observer-as-built.md`
§12 contrasts two cases decided on the same day: CRM passed, because its
containers, volumes, images, vhost, certificate, units and deployment directory
were destroyed on a named host; `acme` did not, because a retired runtime whose
name still resolves and whose rollback archive is intact is not the same
evidence. If you are reasoning from a Knowledge note rather than a measurement,
stop.

## What must move together

Four things, and leaving any one behind is a distinct failure:

| Leave behind | Failure |
| --- | --- |
| the public scrape job | resolution fails (`RESOLUTION-MISSING`) — loud, and the best case |
| the private binding | `RESOLUTION-UNUSED` — a resolved endpoint nothing points at, which is the shape the CRM job had for weeks |
| the alert rules | rules over a metric nobody emits, permanently silent and indistinguishable from "all clear" |
| the credential | a secret file nobody reads and nobody will think to revoke |

The two-directional resolution check is what makes the first two impossible to
get wrong in opposite directions. Removing only the public half fails; removing
only the private half fails. That is deliberate: a one-way check passes while
leaving orphans on the other side.

## Procedure

### 1. Remove the public description

Delete the job from its `inventory/targets/*.toml`. If the product's last job
goes, delete the file. Then:

```
make schema-check
```

It will fail with `RESOLUTION-UNUSED`, naming the now-orphaned binding. **That
failure is the point** — it is the checklist telling you the private half is
still outstanding. Do not silence it by putting the job back.

### 2. Discover — read-only, and it stops there

Actions → *Discover the private inventory shape* → Run workflow, on `main`.

It reports three things and writes nothing: the storage **shape**, the KV
**version**, and the **digest**. It uses the reader identity, so "this does not
write" is a property of the token rather than a promise made by the YAML.

Note all three. Do not print the document — nothing in this procedure requires
you to look at a resolved endpoint, and a terminal scrollback is a place
resolved material should never reach.

**Discovery reports; it does not act.** The earlier design had the mutation
workflow detect the shape and then immediately write, which is detection rather
than confirmation — the same defect as a probe whose result nobody reviews
before acting on it. You are the missing half.

### 3. Write the retirement request

A committed, reviewable file — this is the change, and it is expressed entirely
in logical vocabulary that ADR-0004 already publishes:

```toml
schema_version = "observability-supersession-request.v1"
document = "<the private document's name>"
rationale = "<why these entries are gone, with the evidence>"

[previous]
version = <n>
sha256 = "<the digest from step 2>"

[storage]
shape = "<the shape discovery reported>"

[retire]
targets = ["<logical target id>"]
```

Retiring a target retires its credential binding with it: they are one entry,
and a binding whose credential file has been shredded renders a configuration
the evaluator cannot load.

**The contract has no field for adding anything**, and that is deliberate. A
retirement needs a logical name; a provision needs a resolved endpoint or
credential binding, which must not pass through public Git or a CI input.
Adding an entry stays a human operation against the private store.

### 4. Get it reviewed and merged to `main`

This is the approval. The request is a diff somebody read, on a protected
branch, and the merge is what authorizes it — the same reasoning ADR-0006 §4
gives for the publication exception carrying no `approved_by` field.

### 5. Dispatch the workflow from `main`

Actions → *Supersede the private inventory* → Run workflow, on branch `main`,
with `request` set to the path of the file you merged.

It refuses to run from any other ref. `workflow_dispatch` lets a caller pick
any branch carrying the workflow, so without that guard a branch could supply
both the workflow and the request it applies — the review gate bypassed by
choosing a dropdown value.

The workflow then, in order: refuses a hosted runner and a request path that
escapes the repository; refuses if the public inventory is absent; **verifies
the tool** — lockfile intact, request parsing under its contract — because that
verification is what earns the writer credential; reads the stored version
**confirming the shape the request declared and refusing if the store
disagrees**; applies the request, refusing if the store has moved since the
request was reviewed; **resolves the next version against the public inventory
in both directions**; writes with OpenBao's own `cas` set to the version it
read; reads the stored bytes back and verifies the digest; and shreds its
working copies whether it succeeded or failed.

**The writer credential exists in three steps and nowhere else.** Everything
before the mutation boundary — checkout, the setup actions, `poetry install`,
every dependency it executes — runs with no production credential in the
environment at all. A job-level `env` would have handed the token to all of
them.

**Two compare-and-sets, catching different races.** The request's digest proves
the CONTENT is the version that was reviewed. KV's `cas` proves no version
landed between this run's read and its write. Neither subsumes the other.

Its entire output is digests, counts and logical names. It never emits the
document — not to a log, a job summary, or an artifact, and not on the failure
path, which is where this normally leaks.
`tests/architecture/test_supersession_workflow_cannot_leak.py` enforces that
over the workflow's own text, so a later edit adding an upload step fails the
build rather than the review.

### 6. Confirm

The run's last step prints the read-back digest. Record it; the eventual
deployment plan binds **only** that digest, and a plan carrying the old one
would authorize the environment you have just retired a target from.

The superseded version is retained by KV and nothing in the workflow deletes
it. Do not delete it by hand: every receipt naming version *n* is unresolvable
evidence without version *n* to resolve against.

### The sequence, and why it is a sequence

Every row is outstanding, and each is genuinely gated on the one above it
rather than merely listed after it. Neither workflow can run until all of them
are done, and each refuses rather than improvises when its own prerequisite is
missing.

| # | Prerequisite | Gated on |
| --- | --- | --- |
| 1 | Public inventory populated and reviewed (lane 3C) | — blocks everything |
| 2 | TLS or WireGuard in front of the secret store | Michael's ruling: no credential crosses a plaintext listener |
| 3 | `dotmac-control-runner` provisioned, registered and reachable | 2 — the transport decision must land before another host is put in front of the listener |
| 4 | The runner's egress carried in the private client inventory as an **exact `/32`** | 3 — an allowlist entry for an unprovisioned address is a rule nobody can verify |
| 5 | Reader and writer identities, then their secrets | 4 — a credential the runner cannot use is a credential issued early |
| 6 | `private-inventory` environment configured | 5 |
| 7 | Discovery run once, shape confirmed into a committed request | 6 |
| 8 | Supersession dispatched | 7 |

Row 4 is the one with a rule attached. It is an **exact `/32` for the named
logical role, never the surrounding `/22`** — a `/22` grants a whole office
network reach to a root credential store, and it is precisely why two readers
independently mis-called the store's port publicly reachable on the day it was
contained. If anyone ever proposes restoring the wider range *because the
runner sits inside it*, that is the argument to refuse: the runner's membership
of a range is a reason to name the host, not a reason to admit the range. The
entry goes through the inventory, with an enforcement flag and a stated reason,
never by hand on the host.

Rows 3 and 4 also explain why the workflows behave the way they do while the
runner does not exist. `runs-on` is a literal label pair, so with no matching
runner registered a dispatch stays **queued** — it is not an error, and it is
certainly not rerouted to a hosted runner. Nothing here probes the runner for
liveness, and nothing converts "runner absent" into a failure that would read
like a job problem.

### Before the first run — in this order

The first item is a blocker for everything after it, and the last two are
waiting on names Michael has not given yet.

**1. Populate and review the public inventory** (delivery lane 3C). Both
workflows refuse without it: the two-directional resolution check cannot run,
and a supersession that cannot be resolved is not one worth writing. This is
first, not last.

**2. Provision `dotmac-control-runner`** — a dedicated fixed-egress runner,
registered with the labels `self-hosted` and `dotmac-control-runner`. It is
**not Observer**, **not any product host**, and **not the Foundation test
host**.

Its binding is decided and held privately: logical role and runner label
`dotmac-control-runner`, one fixed egress address carried as an exact `/32`, no
public inbound service, and SSH only from approved management sources. **The
address is not written here** — a resolved host address is private material
under ADR-0004, and this repository's own private-material scanner refuses it
in any tracked file. That is not a formality: the refusal was demonstrated
against this very line before it was written.

"No public inbound service" has a design consequence worth stating rather than
leaving implicit. The runner **reaches out** to the secret store and is never
reached; it exposes nothing. That rules out any later convenience along the
lines of "let CI call a webhook on the runner", which would need an inbound
listener on a host chosen precisely for having none.

> **The control runner and the external probe vantage are opposites, and are
> not interchangeable.** A reader who finds two named VMs in the fleet notes
> might reasonably assume either would serve. They are selected for
> contradictory properties: the control runner is **trusted and inside** Dotmac
> address space, which is what makes an exact `/32` allowlist entry meaningful;
> the probe vantage is **untrusted and outside** every Dotmac allowlist, which
> is the only thing that makes a negative reachability result mean anything. An
> inside host cannot prove a port is closed to the world, and an outside host
> must never hold a credential. Swapping them silently destroys the property
> each was chosen for.

Both workflows pin `runs-on: [self-hosted, dotmac-control-runner]` as a
literal, deliberately not a repository variable. A variable could be repointed
at a hosted runner in repository settings, touching neither workflow nor its
guard and appearing in no diff. With a literal and no matching runner
registered, the job stays **queued** — it is never silently rerouted, which is
the failure that would quietly undo the containment. Each workflow also checks
`RUNNER_ENVIRONMENT` at run time, so a runner registered under a label that
does not describe it is caught too.

OpenBao's listener sits behind an inventory-derived allowlist with a terminal
DROP on both address families. Hosted runners arrive from dynamic ranges, and
widening the allowlist to reach one would undo the containment to serve a
convenience.

**3. Create two identities, path-scoped to this exact document.**

| Identity | Secret | Capabilities |
| --- | --- | --- |
| Reader | `OPENBAO_INVENTORY_READER_TOKEN` | read only |
| Writer | `OPENBAO_INVENTORY_WRITER_TOKEN` | read, CAS update, read-back |

Neither gets `list`, `delete` or `destroy`, and neither reaches an unrelated
path. The split is doing real work: discovery needs no write capability at all,
and the writer needs no list capability. **A single identity that can do both
is the thing to eliminate, not a convenience to preserve.**

Plus `OPENBAO_ADDR`, `OBSERVABILITY_PRIVATE_INVENTORY_MOUNT` and
`OBSERVABILITY_PRIVATE_INVENTORY_PATH`, and
`OBSERVABILITY_PRIVATE_INVENTORY_FIELD` only where the shape is `field`. All are
credential-custody layout and therefore private under ADR-0004, which is why
they are secrets rather than values written down here. Both workflows refuse if
any required one is empty.

**4. Configure the `private-inventory` environment**: deployment branch
restricted to `main`, **no wait timer**, required reviewer **`michaelayoade`**,
and **self-review ALLOWED**.

That last setting is deliberate and is written down here so it does not read as
an oversight. Michael is currently the repository's only eligible collaborator,
so enabling *prevent self-review* would **deadlock the workflow**: the only
person who can approve is the only person who can dispatch. A gate nobody can
pass is not a stronger control, it is an unusable one, and the honest response
is to record why it is off rather than to leave a reviewer wondering.

> **Known interim, with a named target state.** A single-approver gate is a
> real limitation: the approver and the requester are the same person, so the
> environment gate proves deliberateness rather than independent review. The
> target is to **add a second trusted operator or team, then require that
> reviewer AND enable prevent-self-review.** Recording it as an interim is what
> stops it becoming permanent by being forgotten.
>
> This whole gate is itself temporary: it stands in for Deployment Control
> authorization, which is where an approval belongs (ADR-0006 §7). When that
> lands, the environment reviewer is replaced by an `approval_decision_ref`
> resolvable in the system that recorded the decision — a check that does not
> depend on how many collaborators the repository happens to have.

The workflow declares the environment; protection rules live in repository
settings and cannot be asserted from a workflow file, so this is a setup step
and nothing in the repository is evidence that it is done.

**5. Run discovery once** and confirm the shape it reports before writing any
request.

## What this procedure deliberately does not do

**It does not remove the alert rules.** Those are product-owned and travel in a
product bundle; retiring them is the product repository's change, and this
repository only stops pinning the bundle. Deleting a rule here would be
authorship, which `AGENTS.md` § "The line this repository must not cross"
forbids.

**It does not touch the host.** The host-side removal is a separate,
explicitly authorized operation. If it has already happened by hand, record it
as adoption evidence first — `observer-as-built.md` §12 is the worked example —
so the delta the next render must reproduce is written down before anyone tries
to reproduce it.

**It does not promote anything.** A superseded inventory is an input to a
deployment plan, not a deployment. Binding the new digest and refusing on a
census mismatch belong to the promotion lane, which does not exist
(`AGENTS.md` rule 3, `docs/CONTROL_EXCEPTIONS.md`). Until it does, the
comparison between the inventory and the current host census is a human one,
and this is the place it is written down.

**It does not attribute the rules it retires.** Deleting a rule because its
product is gone says nobody needs it; it does not say who wrote it. Where
attribution is still possible, do it first: once the group is off the host, its
authorship is unknowable.
