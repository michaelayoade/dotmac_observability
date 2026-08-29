# Retiring a scrape target

How a decommissioned product leaves the control plane without leaving orphans
behind, and how the private inventory is moved to a new version safely.

Owed by `docs/runbooks/README.md`. It lands with the capability it describes
(`dotmac-observability inventory-supersede`) and not before, per that file's
rule. Everything below is a repository operation plus one private-store write;
**no step touches the Observer host**, and the host-side removal is assumed to
have already happened and been recorded as adoption evidence.

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

### 2. Read the stored private inventory, and record its digest

```
dotmac-observability --contracts contracts inventory-digest <stored>
```

Note the digest. You will name it in step 4, and naming it is what makes the
write safe.

Do not print the document. Nothing in this procedure requires you to look at a
resolved endpoint, and a terminal scrollback is a place resolved material
should never reach.

### 3. Build the next version

Copy the stored document, increment `version` by exactly one, and remove the
retired target's binding **and its credential binding together**. If the
credential file was shredded on the host, the binding must go: a binding whose
file does not exist renders a configuration the evaluator cannot load.

Change nothing else. A version that also carries an unrelated edit cannot be
reviewed as one decision, and the summary in step 4 is what a reviewer reads.

### 4. Prove the succession

```
dotmac-observability --contracts contracts inventory-supersede \
  --previous <stored> --next <new> \
  --expect-previous-sha256 <the digest from step 2>
```

This refuses:

- a previous document that does not hash to the digest you named — somebody
  else wrote a version while you were editing, so **re-read and rebase**, never
  force;
- a renamed document, which is a new document rather than a new version and
  makes every receipt naming the old one unresolvable;
- a changed environment;
- a version that is not exactly one higher;
- a bump that changes nothing.

On success it prints a change summary in **logical names and counts only** —
target ids, credential-ref names, a credential-binding count. It never prints
an endpoint, a store path, a file name or a destination, so the output is safe
to paste into a review.

### 5. Re-validate, both directions

```
make schema-check PRIVATE=<new>
```

Clean output means no public target is unresolved **and** no private binding is
unused. Step 1's failure should now be gone; if it is not, the binding you
removed was not the one the job pointed at.

### 6. Write, then read back

Write the new version to the private store, then verify what the store actually
holds:

```
dotmac-observability --contracts contracts inventory-digest <stored> \
  --expect <the digest inventory-supersede printed>
```

**Do not skip this because step 4 already printed a digest.** That digest
proves the tool could hash a document it was holding in memory. This one proves
the store holds those bytes, and it is the only version of the check that can
fail on a truncated or partial write.

### 7. Retain the superseded version

Do not delete it. Every receipt that names version *n* is unresolvable evidence
without version *n* to resolve against, and a promotion history whose inputs
have been deleted cannot be audited afterwards.

### 8. Rebind before promoting

A deployment plan binds **only the new digest**. A plan carrying the old one
would authorize the environment you have just retired a target from.

Promotion additionally refuses if the current host census disagrees with the
inventory. That check belongs to the promotion lane and does not exist yet
(`AGENTS.md` rule 3, `docs/CONTROL_EXCEPTIONS.md`) — until it does, the
comparison is a human one, and this runbook is the place it is written down.

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

**It does not attribute the rules it retires.** Deleting a rule because its
product is gone says nobody needs it; it does not say who wrote it. Where
attribution is still possible, do it first: once the group is off the host, its
authorship is unknowable.
