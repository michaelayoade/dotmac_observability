# Security posture

What this repository protects, how, and what it explicitly does not protect.
`AGENTS.md` rule 1 is the hard rule; this document is its reasoning and its
boundary. `docs/ARCHITECTURE.md` describes the machinery referred to here.

## The secret-reference model

This repository holds references to secrets. It never holds a secret value, and
it never dereferences one.

A credential is declared as a `secret_file` object with exactly two fields
(`contracts/private-inventory.schema.json` `$defs/secret_file`, loaded into
`model.SecretFile`):

- `openbao_path` — where an operator obtains the value.
- `file_name` — the basename the evaluator will read from its secrets
  directory.

Neither can be turned into a credential by reading it. The value is host state,
placed by the deployment from OpenBao, and OpenBao remains its owner.

**Both strings are nonetheless PRIVATE**, which is the change ADR-0004 made and
the reason that contract is the private one. Rule 1 asks whether a value is a
secret, and by that test both are safe; a store path describes credential
custody layout and a basename says which credential a given target uses, and
both are bindings. Public Git therefore carries a boolean `authenticated` on a
scrape job and a logical `credential_ref` on an integration, and nothing else.
This repository's PR #6 exists because a redaction sweep treated a basename as
clean, which is the whole argument in one incident.

The renderer converts `file_name` into a path under the fixed secrets constant
for the service that will read it, and emits the file-reference form of
whichever field the receiving system expects:

| Where | Rendered field | Directory |
| --- | --- | --- |
| Prometheus scrape job | `bearer_token_file` | `/etc/prometheus/secrets` |
| Prometheus federation | `bearer_token_file` | `/etc/prometheus/secrets` |
| Alertmanager Telegram | `bot_token_file` | `/etc/alertmanager/secrets` |
| Alertmanager email | `auth_password_file` | `/etc/alertmanager/secrets` |
| Alertmanager webhook | `url_file` | `/etc/alertmanager/secrets` |
| Alertmanager Slack | `api_url_file` | `/etc/alertmanager/secrets` |

Note that a webhook and a Slack integration reference the whole URL through a
file, because a webhook URL with an embedded key is a credential regardless of
which field it lives in. There is no rendering path that emits an inline token,
password or URL-with-key, and no code path in `dotmac_observability` that opens
a secrets file or contacts OpenBao. Whether the file exists is the deployment's
problem, checked at promotion time, not this package's.

The basename reaches the renderer from the private inventory rather than from a
committed document, so a rendered artefact carries it and public Git does not.
That is the split working as intended, and it is also the reason a production
render is not committable: see "The two scanners" below and ADR-0006.

`.gitignore` refuses `secrets/`, `*.token`, `*.key` and `*.pem` as a second
line, so a value fetched into a working tree by hand is not accidentally
staged.

## The repository is public

Public, deliberately: branch protection and CI minutes are both unavailable to
a private repository on this account's plan, so the alternative was an
unprotected `main` with no gates at all. ADR-0003 records the trade in full.

The practical consequence for anyone committing here: **rule 1 is necessary
and no longer sufficient.** Rule 1 asks whether a value is a secret. Public
visibility asks a second question — whether a non-secret fact is still
something to publish. A production scrape endpoint, an internal hostname and a
host identity are each non-secret under rule 1, and each is a map for someone
who has got nowhere yet.

ADR-0004 answers that second question, and `AGENTS.md` rule 18 now states the
answer as a hard rule: **public Git carries the logical description of the
control plane; private inventory carries the resolved material.**

Published here: the logical target ID (`erp-production`), the service owner
and environment, metric and alert contracts, expected capabilities, the scrape
protocol, health semantics, the bundle and inventory schemas, the synthetic
`.invalid` CI endpoints, and the version and digest of the private inventory a
render consumed. Withheld: the resolved hostname or IP, the port and complete
scrape URL, TLS and server identity, the credential-file binding —
`openbao_path` included — the federation endpoint, and network-route detail.
That material lives under an approved OpenBao deployment-inventory path or
another private inventory source with a named owner. A promotion resolves the
logical target, validates it against the public schema, renders
deterministically, records the private inventory's version and digest rather
than its values in the receipt, and compares drift by digest without printing
an endpoint. A production endpoint published on purpose needs a per-target
exception carrying a rationale: cleartext is never the default. ADR-0006 §4
records why that exception carries no approver NAME — the approval is the
protected-branch merge, which is externally attested, and a name in a tracked
file is not.

**The split is now enforced, in two independent ways.** ADR-0006 carries the
contracts: `contracts/private-inventory.schema.json` (the document the plan
calls ObserverInventoryV1) holds the resolved material, the public contracts
have no field an endpoint or a credential binding can be typed into, and the
scanner's old check — that every committed `openbao_path` assignment names a
`secret/` store path — inverted into a refusal of the key altogether. Rule 18
left `docs/CONTROL_EXCEPTIONS.md` with that change.

The two ways are complementary rather than redundant, and the second exists
because the first cannot see far enough. Every contract sets
`additionalProperties: false`, so a private field in an inventory document is
refused at the schema layer with a precise error. But neither of this
repository's real disclosures was in an inventory document: PR #4 removed a
rehearsal host address from `ARCHITECTURE.md` and `SECURITY.md`, and PR #6
removed a credential basename from prose. A schema was never going to catch
either, which is what the second scanner is for.

The reason the answer had to precede PR 3 rather than follow it is unchanged
and worth repeating. Git history is not retractable — a value committed to a
public repository and removed in the next commit has still been published, to
every clone, mirror and crawler that touched the repository in between. A
credential answers that by being rotated; a hostname, a port and a network
route do not.


## The two scanners

Two detectors over the same corpus, answering two different questions, and kept
apart deliberately. `validate.scan_for_secret_material` asks rule 1's question —
is this a secret VALUE. `validate.scan_for_private_material` asks rule 18's —
is this a non-secret fact that a public repository should still not carry.

Merging them would be the obvious economy and it would destroy both. The
private detector fires on things that are unambiguously not secrets, so folding
it into the secret scanner would make "secret material found" untrue in most of
its firings; and the secret scanner's patterns are tuned to produce almost no
false positives on this corpus, which is the property that keeps its allowlist
from growing. `tests/mutations/test_private_material_detector_bites.py`
asserts the separation directly: a planted address is found by one and ignored
by the other.

### The secret scanner

`validate.scan_for_secret_material` reads every file Git tracks and reports any
line that looks like it carries a secret value. `make secret-scan` runs it and
is part of `make check`.

The file list comes from `git ls-files -z` rather than a filesystem walk
(`cli._tracked_files`). A walk would have to reimplement `.gitignore` to avoid
scanning a virtualenv, and a scanner that skips files for reasons nobody wrote
down is how a real finding gets lost.

### Shape, not entropy

The detector is a fixed set of shape patterns:

| Code | Shape |
| --- | --- |
| `SECRET-PEM-PRIVATE-KEY` | A PEM private-key header |
| `SECRET-TELEGRAM-BOT-TOKEN` | An 8-to-10 digit id, a colon, and 35 token characters |
| `SECRET-SLACK-WEBHOOK` | A `hooks.slack.com/services/` URL |
| `SECRET-AWS-ACCESS-KEY` | `AKIA` followed by 16 uppercase alphanumerics |
| `SECRET-ASSIGNED-CREDENTIAL` | A credential-shaped key name assigned a value of 16 or more characters |

It is deliberately not entropy-based, and this is a decision rather than an
omission. An entropy threshold flags high-entropy strings, and this repository
is made of high-entropy strings that are not secrets: every `sha256:` image
digest in the control-plane document, every `rules_sha256` and
`metrics_manifest_sha256` in a bundle lock, every 40-character
`source_revision`, and every `rendered_digest` in a receipt. A bundle lock is
close to nothing but digests.

The consequence is predictable and it is the real argument. A detector that
cries wolf on legitimate content acquires an allowlist, the allowlist grows
with each new lock file, and the endpoint is a detector that detects nothing
while still appearing in `make check`. Shape patterns produce few false
positives on this corpus, so the allowlist has no pressure to grow, so the
detector stays honest. A missed exotic credential shape is a gap to close by
adding a pattern; a disabled detector is not recoverable by anything short of
noticing.

### The two exclusions, and their premise

`validate.SECRET_SCAN_EXCLUSIONS` is exactly two paths:

```
src/dotmac_observability/validate.py
tests/mutations/test_secret_detector_bites.py
```

`AGENTS.md` rule 15 requires that an exemption state an enforceable premise
rather than a convenience. The premise here is that these two files are the
detector and its sensitivity proof: they must contain the shapes being
detected, because the patterns live in one and the evidence that the patterns
bite lives in the other. Excluding them is not a relaxation of the rule; it is
the only way the rule can have evidence at all. A check over a corpus that
contains none of the thing it detects passes for the wrong reason.

Nothing else may be added to that tuple. The list is asserted exactly, not
merely bounded, by `tests/architecture/test_no_secret_material.py`, so widening
it fails the build rather than passing quietly; and the second excluded path,
`tests/mutations/test_secret_detector_bites.py`, is the sensitivity proof
itself. Both exist. A scanner whose corpus contains none of the shapes it looks
for cannot demonstrate that it bites, and an undemonstrated detector is an
unmonitored region wearing a green tick.

### The private-material scanner

`validate.scan_for_private_material` reads the same corpus and reports resolved
material. `make private-scan` runs it and is part of `make check`.

| Code | Shape |
| --- | --- |
| `PRIVATE-ADDRESS` | A non-loopback IPv4 literal |
| `PRIVATE-ADDRESS-V6` | An IPv6 literal, in the abbreviated forms tools actually print |
| `PRIVATE-HOSTNAME` | A subdomain of a real Dotmac domain |
| `PRIVATE-STORE-PATH` | An OpenBao path of two or more segments, outside the reserved fixture prefix |

Three of the four exclusions a reader might expect are absent, and each absence
is the design rather than an oversight.

**Loopback is published, not exempted.** `127.0.0.1` describes this control
plane's own posture, which is the evidence the "loopback-bound listeners"
section below relies on, and the `LISTEN-NOT-LOOPBACK` gate refuses any other
address in a public document. So the pattern skips loopback because loopback is
public, not because it is being let through.

**The bare schema domain is not a host.** The contracts carry
`https://dotmac.io/schemas/...` identifiers, which name a namespace nobody can
connect to. The hostname pattern requires a leading label, so a subdomain is
caught and the namespace is not — no allowlist entry, just a stricter pattern.

**The synthetic private inventory is exempt by PREFIX, not by path.** Its store
paths are under `secret/fixture/`, a reserved namespace that names nothing
real. Excluding the file would have been easier and strictly worse: a genuine
store path pasted into that file would then go unnoticed. As written, it does
not. `tests/architecture/test_public_inventory_carries_no_private_material.py`
proves both halves — that every fixture endpoint is an unresolvable `.invalid`
name and every fixture path is under the reserved prefix, and that swapping one
prefix for a real one is still caught.

Two paths ARE excluded, on the same premise the secret scanner's exclusions
carry: `validate.py` holds the patterns and
`tests/mutations/test_private_material_detector_bites.py` holds the proof that
they bite, so both must contain the shapes being detected. The same premise
gives `validate.py` the one exemption in
`test_repository_contract.py::test_no_source_file_hardcodes_a_host` — and that
exemption is itself checked, because a premise nobody verifies is a comment: a
companion test fails if the domain ever appears there as a plain literal rather
than inside a regex.

### What a production render is, and where it lives

A consequence of the split, stated here because it surprises people. Public
inputs plus the public contracts render the SYNTHETIC fixture and nothing else.
A production render needs the private inventory, produces bytes that legitimately
contain resolved endpoints and credential basenames, and is therefore **not a
committable artefact**. It is produced at promotion time, hashed, and recorded
by digest.

`deploy/rendered/` is consequently empty in Git and stays that way. `make
render-check` compares the reference fixture's committed bytes against a fresh
render of the same synthetic inputs, which is exactly as strong a determinism
gate as before — determinism is a property of the renderer and its inputs, not
of whether those inputs are real.

## The receipt carries no secret

`contracts/promotion-receipt.schema.json` sets `additionalProperties: false` at
every level, and every field it does permit is a count, a boolean, a digest, a
revision, a version string, a LOGICAL name or a timestamp. There is no free-text
field a value could be pasted into and no field whose type would accept one.

`host.identity` used to be on that list and is now `host.target_id`, for
ADR-0004's reason: a receipt is the artifact most likely to leave the
repository's access controls, so it names the host logically and lets a reader
who has the private inventory — whose digest the receipt also carries —
establish which machine was changed. A reader with neither learns nothing.

The receipt additionally records the approved plan it executed, the private
inventory it resolved against, and the exact image digests, all three by
identity rather than by value. That is what makes the repository's claim
checkable — **every controller-owned image and deployment-relevant
configuration byte explained by an authorized digest** (ADR-0007) — because a
reader can re-derive each digest and compare without any of the three
disclosing what it resolved to.

The plan reference is `plan_digest` plus `approval_decision_ref`, and it is
CONSUMED rather than defined: `dotmac-deployment-control` owns approval, and
this repository records which approved plan it carried out (ADR-0006 §7).
There is deliberately no approver name in it — a decision reference resolvable
in the system that took the decision is checkable, and a string is not.

This matters more than it looks, because a receipt is the artifact most likely
to be attached to a ticket, pasted into a channel or archived somewhere with
weaker access control than the repository. `canary.delivered` is a boolean and
`canary.receiver` is a receiver name: the receipt records that a named receiver
was reached, never how it was reached.

## Runtime posture of the rendered stack

- **Loopback-bound listeners.** `model.Evaluator.listen` carries a full
  host-and-port, and the reference inventory binds both evaluators to
  `127.0.0.1`. The rendered compose publishes
  `${PROMETHEUS_LISTEN:-<listen>}:<port>`, so the default keeps the port off
  every non-loopback interface and reaching it is an explicit act (an SSH
  tunnel, or a reverse proxy the host owns). Overriding the variable to
  `0.0.0.0` is possible and is a decision an operator makes deliberately, not a
  default anyone can inherit.
- **Read-only mounts.** Every configuration and secrets mount in the rendered
  compose is `:ro`. Only the named data volumes (`prometheus_data`,
  `alertmanager_data`) are writable. A compromised evaluator process cannot
  rewrite its own rules or read anything outside the two directories mounted
  into it.
- **Unprivileged users.** Both services run as `${PROMETHEUS_USER:-65534:65534}`
  and `${ALERTMANAGER_USER:-65534:65534}`, that is, `nobody` by default.
- **Digest-pinned images.** Images are `image@sha256:...`, never a tag. A tag is
  a mutable pointer, so a restart under a tag can silently change the running
  binary; the receipt could then name a version that is not what ran.
- **One required variable.** `OBSERVABILITY_RELEASE` is rendered as
  `${OBSERVABILITY_RELEASE:?release directory is required}` with no default,
  because a stack that silently starts against the wrong release is worse than
  one that refuses to start.

## The ingestion boundary: authentication, not address allowlisting

The "loopback-bound listeners" bullet above covers the rendered evaluators,
which are not the problem precisely because they are loopback-bound. Loki is, because it has six live remote log
shippers and cannot be loopback-bound. This section is the posture for that
surface and for any future one like it. ADR-0005 holds the full argument;
`AGENTS.md` rule 19 states it as a hard rule, and **none of it is enforced
yet** — the guard ships with the `dotmac-deployment-foundation` release that
carries `IngressPolicy.v1`, not with a pull request here.

### Why an address allowlist is not the boundary

Until this decision, the only thing between a remote shipper and Loki's
ingestion API was a set of IPv4 `DOCKER-USER` rules. The API accepted whatever
reached it. Three properties make that insufficient, and none of them improves
with maintenance:

- **An address allowlist authenticates a network position, not a shipper.** It
  admits whoever currently occupies an address. Nothing in the traffic proves
  which sender produced it, so no accepted write can be attributed.
- **It cannot revoke one shipper without disturbing the others.** Several
  shippers can share one NAT egress address, so the blast radius of removing an
  entry is whoever else sits behind it. A revocation nobody dares perform is
  not a revocation.
- **It breaks when a NAT egress address changes, and this fleet has observed
  exactly that.** The census records a shipper whose hostname resolves to an
  address that never connects; it arrives from a different address in the same
  autonomous system (`docs/inventories/observer-as-built.md` §9.1). Each such
  break is repaired by widening the allowlist.

Beneath all three, ingestion is unauthenticated on the wire: the bytes carry no
credential and no transport identity.

The proposal to bind Loki to an explicit IPv4 address, so the working IPv4
allowlist covers it, is **emergency containment only and not the architecture**
— a reasonable thing to do in an hour, and the three properties above are
unchanged by doing it.

### What replaces it

A reusable authenticated ingress on 443, owned by
`dotmac-deployment-foundation` and adopted here. It terminates TLS, is
dual-stack capable, and requires per-shipper mTLS or per-shipper credentials
before a request reaches an upstream. Loki declares exposure `ingress` and
publishes no host port of its own; Prometheus, Alertmanager, node-exporter and
raw Loki are internal-only. Every published surface declares its exposure and
its address family, both mandatory and neither defaulted, and a bare
`PORT:PORT` publish, an unauthenticated `public` surface, and a backend that
sits behind an ingress while also publishing its own host port are each
refused. `docs/ARCHITECTURE.md` §"The exposure model" describes the mechanics.

### What an ingress credential is, and where it lives

One credential per shipper, and per-shipper is the whole point. Either a client
certificate the ingress verifies at the TLS handshake, or a bearer credential
the ingress checks before proxying — the choice is per shipper and is part of
the policy, not a property of Loki.

The credential value lives in an approved private store, alongside the
certificates and the resolved addresses this boundary needs (ADR-0004,
ADR-0005). **No path to it appears in this repository**, and neither does the
binding that says which shipper uses which credential: a store path describes
credential custody layout, which is private material under ADR-0004, and the
binding names both a sender and its key location in one string. This is
stricter than the secret-reference model described at the top of this document,
deliberately and in the same direction ADR-0004 already moved it.

What is public is the posture: that ingestion is authenticated, that
authentication is per shipper, that the transport is TLS, and which address
families are declared. Publishing the posture is what lets a reviewer disagree
with it. Publishing the resolution would be a map.

### What revocation means

Revoking one shipper removes one credential. The other five continue
uninterrupted, no rule is edited, no address is touched, and no other sender's
delivery is at risk while the change is made. The revoked shipper is refused at
the ingress and the refusal is attributable, so a revocation that was a mistake
is visible as a named sender being turned away rather than as logs quietly
stopping.

This is the single property that most distinguishes the new boundary from the
old one, and it is why conformance has to prove refusal and recovery — that a
revoked credential is rejected, and that a restored legitimate one resumes
delivery — rather than only proving that ingestion works.

### A firewall is a second line, and never the first

This warning is standing, and it applies after the ingress exists as much as
before.

The correct firewall fix on the Observer host is an `INPUT` rule, because
`docker-proxy` terminates a published connection locally and the traffic never
traverses `FORWARD` — which is why the IPv6 rules in the `ip6tables`
`DOCKER-USER` chain have never fired and cannot. That fix is blocked: an
`INPUT` rule carries SSH, and out-of-band recovery on this host is present but
unproven, with no working root password confirmed. It stays blocked until
recovery is demonstrated, not asserted.

Two conclusions follow. First, no surface may be published on the premise that
a firewall will contain it, because that premise has now been measured false on
this host and the same inert idiom was applied across the fleet in the
2026-08-14 sweep. Authentication is the boundary; packet filtering narrows the
population that can reach it. Second, when `INPUT` hardening does become safe,
it is added behind a boundary that already authenticates — a second line — and
adding it does not retire the first.

Until phase 6 of the ADR-0005 cutover, raw Loki keeps its publication while
shippers migrate, so two ingestion paths are live at once and the posture is
the weaker of the two. That is stated here rather than in the ADR alone because
anyone reading this document during the migration is reading it about a system
that has not yet finished getting the property it describes.

## Promotion authority

A promotion targets a host a human named in the authorizing request
(`AGENTS.md` rule 17). It is never inferred from an inventory row, and this is
worth stating precisely because a resolvable target now exists in the private
inventory: `host.identity` and `host.ssh_alias` live there, under the logical
`host.target_id` the public control-plane document declares. Those fields exist
so the receipt can record which host was promoted to and so an operator can
check that the named target and the declared one agree. They are not an
instruction to connect anywhere.

The binding that makes those four things one decision — release, inventory,
render and images — is real, and it belongs to `dotmac-deployment-control`,
which owns deployment intent, plan freezing, approval policy and the approval
decision. Any three of them agreeing proves nothing about the fourth, so they
are bound in one frozen, approved plan rather than checked one at a time.

This repository is the first ADOPTER of that control plane and not a second
one. It consumes an approved plan, records `plan_digest` and
`approval_decision_ref` in the receipt, defines no approval or signature
semantics in any contract, and carries no self-attested approver anywhere.
`AGENTS.md` rule 20 states it and
`tests/architecture/test_authorization_is_not_owned_here.py` enforces it. Until
the owner's dedicated repository lands, this repository depends on the
published contract and vendors no copy: a local copy would be a second answer
to who may deploy.

The same rule governs the delivery train. PR 2's census is blocked, not
delayed, because it needs Michael to name the Observer SSH target explicitly.
PR 5 rehearses on the dedicated test server, and PR 7's production
bootstrap is authorized separately from the PR that writes it.

Every promotion also targets an exact protected-`main` SHA reasserted as
current at promotion time (`AGENTS.md` rule 3). A branch name, a tag alone or
"latest" is not a promotion target: a repository-local claim may be derived
from repository-local facts, but a claim that a bundle is published requires an
external oracle carrying immutable coordinates. Enforcement is PR 6.

## What this repository does not defend against

**A host operator with root.** Somebody with root on the Observer host can edit
a staged release directory, replace a secrets file, swap the release pointer,
or run a different compose file entirely. Nothing here prevents that, and no
amount of Git ownership can: the host is where the bytes finally live.

What the design provides instead is detection. Because the desired state, the
live state and the last verified receipt are three independently readable
artifacts (`docs/ARCHITECTURE.md` §"Three independently comparable artifacts"),
an edit made on the host shows up as a disagreement between them, with enough
detail to say which of the three moved. `AGENTS.md` rule 2 then makes the
response unambiguous: a change made on the host is drift to be reported and
reverted, never a fix to be kept. Drift comparison is PR 6; until it exists,
this repository detects nothing on the host at all, and saying otherwise would
be the exact overclaim rule 15 exists to prevent.

Also out of scope: the security of the products being scraped, the contents of
product alert bundles (the product repository owns those and their review), the
OpenBao deployment itself, and network reachability between the Observer host
and its scrape targets.
