# ADR-0006: The private inventory, and the deployment authorization that binds it

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Implements:** `docs/adr/0004-public-logical-inventory-private-promotion-material.md`
- **Related:** `AGENTS.md` rules 1, 3, 4, 17, 18 and 20, `docs/SECURITY.md`,
  `docs/adr/0002-deterministic-rendering-and-immutable-releases.md`

## Context

ADR-0004 decided the split and deliberately did not build it. It named the
fields that had to move, flagged two classifications it declined to settle
without more thought, and set the sequencing rule that matters most: the
contracts must change **before** any production inventory is written, because
Git history is not retractable and the first production-inventory commit is the
one that cannot be corrected afterwards.

This ADR is that change. It is the whole of delivery-train lane 3B, and it
unblocks 3C.

There is a second thing ADR-0004 did not address, and it becomes urgent the
moment the split exists. Once the inputs live in two places, a deployment is
assembled from four independently produced things — a control-plane release
built from a reviewed commit, a private inventory resolved separately, a
configuration rendered from the two, and container images pulled from upstream.
Any three of them agreeing proves nothing whatever about the fourth. The
Observer host demonstrates the failure precisely: seven images float on
`:latest`, so what ran yesterday and what runs after tonight's restart are two
different deployments with one description
(`docs/inventories/observer-as-built.md` OBS-02).

## Decision

### 1. The private inventory is a contract, and the contract is public

`contracts/private-inventory.schema.json` defines
`observability-private-inventory.v1` — the document the delivery plan calls
**ObserverInventoryV1**. It holds resolved endpoints, credential bindings,
receiver destinations, and the host's real identity and SSH alias.

**The schema is public and every instance is private.** That is not a
contradiction. A schema describes the shape of resolved material, which
discloses nothing; an instance *is* the resolved material. Publishing the shape
is what lets a reviewer disagree with the split, which is the same argument
ADR-0003 makes for the repository being public at all.

The canonical form is fixed in the contract rather than left to a convention:
UTF-8, sorted keys, two-space indent, **no trailing newline**. A reader that
appends a newline before hashing reports drift on an inventory that has not
changed, and "the digest disagrees" is the least debuggable failure a promotion
can produce. The digest is taken over the document as *parsed and
re-serialised*, so a reformat is not drift while a changed value is.

### 2. Public documents carry logical identity and capability, and nothing else

| Was | Is |
| --- | --- |
| `scrape_job.endpoints` | `scrape_job.target_id`, resolved privately |
| `scrape_job.credential` (`openbao_path`, `file_name`) | `scrape_job.authenticated`, a boolean |
| `federation.source.endpoint` | `federation.target_id` |
| `federation.source.credential` | `federation.source.authenticated` |
| `integration.credential` | `integration.credential_ref`, a logical name |
| `integration.destination` | resolved privately |
| `host.identity`, `host.ssh_alias` | `host.target_id` |

`observability-target`, `observability-control-plane`, `observability-routing`
and `observability-promotion-receipt` all move to `.v2`. A contract whose
required fields change is a different contract, and this repository's own rule
4 — a version string is not an identity — applies to its own schemas first.

`integration.destination` moving is worth stating separately because it is the
one entry above that ADR-0004 did not name. A chat id or a mailbox identifies a
real channel and a real audience; the delivery plan lists routing destinations
as authorization-time material, and it is right.

### 3. `authenticated` is a capability, and resolution makes it falsifiable

The interesting property of a boolean where a credential used to be is that the
public half now makes a *claim* the private half can contradict. Resolution
refuses the disagreement in both directions: a job declaring
`authenticated = true` against a binding with no credential, and — the one
that matters operationally — a binding carrying a credential that no job admits
to using, which is a credential nobody will think to revoke.

Without that gate `authenticated` would be a comment. With it, a reviewer
reading only public Git can see which targets are meant to authenticate, and a
promotion proves the claim before rendering anything.

### 4. The per-target exception is enforced by construction

ADR-0004 asked for a gate refusing a public endpoint with no reviewed exception
block. There is no gate, and that is stronger rather than weaker: **there is no
field an endpoint can be typed into except one that also requires a rationale,
a named approver and a date.** The exception cannot be taken by omission
because omission is not a shape the contract accepts.

A `publication` block is also the resolution for that target, used instead of a
private binding rather than alongside one. A target with both is refused
(`PUBLICATION-SHADOWED`): two answers to one question, with nothing comparing
them.

### 5. Both of ADR-0004's open classifications, settled

**`metrics_path` is PUBLIC, and a non-default value must explain itself.** The
conventional path is scrape protocol and discloses nothing. ADR-0004 correctly
identified the ambiguous case — a path chosen precisely because it is not
guessable is topology wearing a protocol field's name — and a gate cannot tell
the two apart. So the gate does not try: `METRICS-PATH-UNEXPLAINED` requires a
`path_rationale` on any path that is not `/metrics`, which makes the author say
which one it is. That is the honest limit of what a check can do here.

**`listen` is PUBLIC while its address is a loopback address, and refused
otherwise.** A loopback bind describes this control plane's own posture, is the
documented default of the public software being run, and is the evidence
`docs/SECURITY.md` cites that the rendered stack keeps its ports off every
non-loopback interface — evidence that disappears if the value is withheld. Any
other address is a resolved bind address. ADR-0004 flagged this exact
conditional as "the kind of rule that needs writing down as a gate rather than
a habit"; `LISTEN-NOT-LOOPBACK` is that gate.

### 6. Resolution is a separate value, produced once, after it is checked

`validate.resolve(state, inventory)` returns a `Resolution` or raises. The
renderer takes one and indexes it without guarding, so a `KeyError` there would
be a bug in the resolver rather than a malformed input.

A renderer that resolved as it went would meet a missing binding half-way
through emitting a file and would report the first failure rather than all of
them — the same reason every other layer in this repository returns findings
instead of raising one at a time.

Resolution checks in **both** directions. The unresolved public target is the
obvious half. The unused private binding is the half that gets left out, and it
is the one that describes a resolved endpoint nobody points at — the exact
shape of the CRM scrape job that outlived its product on the Observer host by
weeks (`docs/inventories/observer-as-built.md` §12).

### 7. The deployment authorization binds all four

`contracts/deployment-authorization.schema.json` defines one document, written
before a promotion runs, naming:

- the control-plane release revision (an exact protected-`main` SHA) and its
  bundle digest;
- the private inventory's document, version and digest;
- the rendered configuration digest;
- every container image, by repository and `sha256:` digest;
- the logical target host;
- a named approver, with a rationale of substance and a timestamp.

Release digest and rendered digest are deliberately separate fields. The bundle
is what was built once; the render is what that bundle plus one environment
produced. Recording only one makes it impossible to say afterwards whether a
difference came from the software or from the environment — which is the
question the whole build-once/bind-late arrangement exists to be able to
answer.

Like the private inventory, the schema is public and every instance is private,
because an instance names a host and an approver. The promotion receipt records
its identity and digest only.

`AGENTS.md` rule 20 states this as a hard rule and it is `none yet (PR 6)`:
the contract exists and every digest it names can already be produced, but
nothing writes an authorization because nothing promotes. A check over a
document no code emits passes on the empty set, and this repository does not
count that as enforcement.

### 8. Two scanners, because rule 1 and rule 18 ask different questions

`scan_for_secret_material` asks whether a value is a SECRET.
`scan_for_private_material` asks whether a non-secret fact is still something a
public repository should carry. Merging them would make "secret material found"
untrue in most of the second detector's firings, and would put pressure on the
first detector's allowlist — which is the property that keeps it honest.

The scan exists because the structural half cannot see far enough. Closed
contracts refuse a private field in an inventory document with a precise error.
But **neither of this repository's real disclosures was in an inventory
document**: PR #4 removed a rehearsal host address from `ARCHITECTURE.md` and
`SECURITY.md`, and PR #6 removed a credential basename from prose that an
earlier sweep had passed as clean. A schema was never going to catch either.

Three exclusions a reader would expect are absent, and each absence is the
design:

- Loopback is skipped because loopback is *published* (§5), not because it is
  let through.
- The bare schema-namespace domain is not matched because the pattern requires
  a leading label — a stricter pattern rather than an allowlist entry.
- The synthetic private inventory is exempt **by reserved prefix, not by
  path**. Its store paths are under `secret/fixture/`, which names no real
  namespace. Excluding the file would have been easier and strictly worse: a
  genuine store path pasted into that file would then go unnoticed. As written
  it does not, and a test proves it by planting one.

## Consequences

### A production render is not a committable artefact

This is the largest practical consequence and it deserves stating plainly.
Public inputs plus the public contracts render the synthetic fixture and
nothing else. A production render needs the private inventory and produces
bytes that legitimately contain resolved endpoints and credential basenames.
It is produced at promotion time, hashed, and recorded by digest.

`deploy/rendered/` is therefore empty in Git and stays that way. `make
render-check` now compares the reference fixture's committed bytes against a
fresh render of the same synthetic inputs — exactly as strong a determinism
gate as before, because determinism is a property of the renderer and its
inputs rather than of whether those inputs are real.

### `render-check` and `schema-check` join `make check` early

They were scheduled for lane 3C, blocked on "no production inventory to
validate". Under this decision there will never be one in the repository, so
waiting would have meant waiting forever. Pointing them at the fixture makes
them meaningful today, and the CI matrix gains all three new targets in the
same commit — the matrix must equal `make check` exactly, and a matrix naming a
subset is a known past failure on this fleet.

### CI stops rendering by a second path

The `config-validation` job inlined a Python script, on the argument that a
root/contracts split was CI-only and a flag for it would contort the production
adapter. That argument is reversed here: a promotion loads public inventory
from one place and a private inventory from another, so a caller whose root and
contracts differ is the normal case. `--contracts` earns its place, and the job
now renders through the CLI.

The reversal also closed a real gap rather than merely tidying one. The inline
script was a second caller of the library and it had already drifted — it
applied the semantic gate while the CLI grew a resolution gate the script did
not have. A job that renders by a different path than production proves the
wrong thing.

### What a public reader loses

Reproducibility by a stranger, which ADR-0004 already accepted and priced. Two
specific checks also move out of a public reader's reach — the Telegram chat-id
check and the `expected` up-count check — because both read values that are now
private. What is lost is the check, not the guarantee: a promotion supplies the
inventory and cannot skip either.

### What it costs operationally

A promotion depends on a second system being reachable and correct. If the
private inventory is unavailable, nothing can be promoted. That is the same
dependency credentials already carried, widened, and it is a failure that stops
a promotion rather than one that corrupts a release.

## Alternatives considered

**Keep endpoints public and redact at render time.** Already rejected by
ADR-0004 and worth restating because it keeps looking attractive: it leaves the
values in Git, world-readable, in the inputs the whole repository exists to
make reviewable. It protects the artefact that was never the exposure.

**One scanner with more patterns.** Rejected in §8. The two detectors have
opposite tuning pressures — the secret scanner must stay quiet on a corpus made
of digests, the private scanner must fire on ordinary-looking addresses — and a
single allowlist serving both would grow until neither bit.

**Exempt the fixture directory from the private scan.** Rejected in §8. It is
the arrangement that fails silently: the file would then be trusted rather than
checked, and the property that makes it safe would stop being verified at the
moment somebody edited it.

**Let the renderer resolve as it goes, and drop the `Resolution` type.**
Rejected in §6. Fewer types, worse failures: the first missing binding aborts a
half-written file, and the operator fixes one problem per run.

**Fold the authorization into the promotion receipt.** Rejected. A receipt
records what happened; an authorization records what is permitted to happen,
and it must exist before the thing it authorizes. One document serving both
purposes can only ever be written afterwards, at which point it authorizes
nothing.
