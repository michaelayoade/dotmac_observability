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

### 2. Read the stored digest

Whoever holds access runs, or the workflow's first run reports:

```
dotmac-observability --contracts contracts inventory-digest <stored>
```

Note the digest. Do not print the document. Nothing in this procedure requires
you to look at a resolved endpoint, and a terminal scrollback is a place
resolved material should never reach.

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

The workflow then, in order: reads the stored version; records its digest;
applies the request, refusing if the store has moved since the request was
reviewed; **resolves the next version against the public inventory in both
directions**; writes with OpenBao's own `cas` set to the version it read; reads
the stored bytes back and verifies the digest; and shreds its working copies
whether it succeeded or failed.

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

### Before the first run — setup this runbook cannot verify

- The `private-inventory` environment must exist with **required reviewers**.
  The workflow declares the environment; protection rules are configured in
  repository settings and cannot be asserted from the workflow file, so this
  line is a setup step and not evidence that it is in place.
- Four secrets must be configured: the OpenBao address and token, and the
  mount and path of the document. All four are credential-custody layout and
  therefore private under ADR-0004, which is why they are secrets rather than
  values written down here. The workflow refuses to continue if any is empty.
- The storage shape is **detected, not assumed**: the workflow reports whether
  the document is the secret's data object or a single field, and refuses if it
  can identify neither. Confirm which it found on the first run.
- `inventory/` must be populated (delivery lane 3C). The workflow refuses
  otherwise, because the two-directional resolution check cannot run and a
  supersession that cannot be resolved is not one worth writing.

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
