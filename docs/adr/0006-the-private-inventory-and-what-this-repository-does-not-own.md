# ADR-0006: The private inventory, and what this repository does not own

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Implements:** `docs/adr/0004-public-logical-inventory-private-promotion-material.md`
- **Related:** `AGENTS.md` rules 1, 3, 4, 17, 18 and 20, `docs/SECURITY.md`,
  `docs/adr/0002-deterministic-rendering-and-immutable-releases.md`,
  `docs/adr/0007-the-controller-owned-release-boundary.md`

## Context

ADR-0004 decided the public/private split and deliberately did not build it. It
named the fields that had to move, flagged two classifications it declined to
settle without more thought, and set the sequencing rule that matters most: the
contracts must change **before** any production inventory is written, because
Git history is not retractable and the first production-inventory commit is the
one that cannot be corrected afterwards.

This ADR is that change. It is delivery-train lane 3B, and it unblocks 3C.

### The correction this ADR carries in its title

An earlier draft of this decision went further than it was entitled to. Having
established that inputs now live in two places, it observed — correctly — that
a deployment is assembled from four independently produced things (a release
built from a reviewed commit, an inventory resolved separately, a render made
from the two, and images pulled from upstream), and that any three of them
agreeing proves nothing about the fourth. Observer demonstrates the failure
exactly: seven images floating on `:latest`, so what ran yesterday and what runs
after tonight's restart are two different deployments with one description
(`docs/inventories/observer-as-built.md` OBS-02).

The draft then drew the wrong conclusion and defined a
`DeploymentAuthorization` contract **here**. That was wrong twice over, and the
reasons are worth recording because they are the kind that recur.

**It made an adopter into an owner.** `dotmac-deployment-control` already owns
deployment intent, plan freezing, approval policy and the approval decision. It
is published at `0.1.0a2` and its `README` already draws this exact boundary
from the other side: *"No health status at all. Whether a deployment is UP
belongs to Dotmac Observability."* Defining authorization here would have made
the boundary asymmetric — they refuse to own health, and we would have owned
their approvals.

**It attested an approval to itself.** The draft's authorization carried
`approver.name`, and its per-target publication exception carried
`approved_by`. Both are self-attested: nothing verifies the string, the person
named is never notified, and the result is an approval record that looks
checkable and is not. The owning module had already got this right and the
draft did not look: `dotmac-deployment-control` records
`approval_policy_code`, `approval_policy_version`, `approval_decision_ref` and
`approved_at` — a decision taken under a named, versioned policy, resolvable in
the system that took it, with **no name column anywhere**.

So the four-way binding argument stands and the ownership does not. The binding
is real and it belongs to the control plane; this repository consumes an
approved plan and records which one it executed.

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
real channel and a real audience.

### 3. `authenticated` is a capability, and resolution makes it falsifiable

The interesting property of a boolean where a credential used to be is that the
public half now makes a *claim* the private half can contradict. Resolution
refuses the disagreement in both directions: a job declaring
`authenticated = true` against a binding with no credential, and — the one that
matters operationally — a binding carrying a credential that no job admits to
using, which is a credential nobody will think to revoke.

Without that gate `authenticated` would be a comment.

### 4. The per-target exception is enforced by construction, and carries no approver

ADR-0004 asked for a gate refusing a public endpoint with no reviewed exception
block. There is no gate, and that is stronger rather than weaker: **there is no
field an endpoint can be typed into except one that also requires a
rationale.** The exception cannot be taken by omission because omission is not
a shape the contract accepts.

What the block does *not* carry is an approver, and removing that field was a
correction rather than a simplification. The rationale stays, because a
reviewer must be able to disagree with it and because it is what stops the
exception being available by omission. The approval is the protected-branch
merge that accepted the rationale — externally attested, with immutable
coordinates, exactly the oracle Governance ADR 0013 asks for. A name in the
file would have added a second, weaker claim about the same event.

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

### 7. Authorization is consumed, never defined here

`dotmac-deployment-control` owns deployment intent, plan freezing, approval
policy and the approval decision. This repository:

- consumes an **approved plan** and records which one it executed, as a
  `plan_digest` plus an `approval_decision_ref` resolvable in the system that
  took the decision, with the policy code and version when the owner supplies
  them;
- defines **no** approval or signature semantics in any contract;
- carries **no** self-attested approver field anywhere.

`AGENTS.md` rule 20 states this and
`tests/architecture/test_authorization_is_not_owned_here.py` enforces it: no
contract may define an `authorization`, `approval`, `signature` or
`attestation`, and no contract may carry an `approved_by`-shaped field. The
detector plants the removed field back into the real publication block to prove
it bites.

Until the owner's dedicated repository lands, this repository **depends on the
published contract and vendors no copy of it.** A local copy would be a second
answer to who may deploy, which is the whole failure being avoided.

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
bytes that legitimately contain resolved endpoints and credential basenames. It
is produced at promotion time, hashed, and recorded by digest.

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

A promotion depends on two other systems being reachable and correct: the
private inventory, and the deployment control plane that approves the plan. If
either is unavailable, nothing can be promoted. That is the same dependency
credentials already carried, widened, and both are failures that stop a
promotion rather than ones that corrupt a release.

## Alternatives considered

**Keep endpoints public and redact at render time.** Already rejected by
ADR-0004 and worth restating because it keeps looking attractive: it leaves the
values in Git, world-readable, in the inputs the whole repository exists to
make reviewable. It protects the artefact that was never the exposure.

**Define the authorization here anyway, and reconcile later.** Rejected, and it
was the draft this ADR corrects. Two owners of one decision do not reconcile;
they diverge, and the divergence is discovered by a deployment that one of them
approved. The published module exists, so "later" would have meant importing a
conflict rather than avoiding one.

**Vendor a copy of the control plane's authorization contract.** Rejected. A
vendored copy is a fork with a friendly name: it drifts silently, and the day
it disagrees with the owner there is no rule saying which is right. A pinned
dependency on the published contract has an answer to that question.

**Keep `approved_by` on the publication block only, since it is a disclosure
rather than a deployment.** Tempting, and rejected. The field's weakness has
nothing to do with which decision it records: it is unverified in both cases.
Keeping one self-attested approver would have preserved the habit and the
precedent, and the merge already attests the same event properly.

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
