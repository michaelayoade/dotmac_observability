# Architecture

As-built truth for `dotmac_observability`. `AGENTS.md` holds the hard rules and
wins on any disagreement; `docs/adr/` holds the decisions and their status;
`README.md` is onboarding. Anything below that describes behaviour the code
does not have is a defect in this file.

Read this alongside `docs/adr/0001-observability-control-plane-has-one-git-owner.md`
(why the owner exists and where its authority stops),
`docs/adr/0002-deterministic-rendering-and-immutable-releases.md` (why the
bytes are committed and why activation swaps a directory) and
`docs/adr/0006-the-private-inventory-and-what-this-repository-does-not-own.md`
(why the inputs are in two places, and why authorization is consumed rather
than defined here) and
`docs/adr/0007-the-controller-owned-release-boundary.md` (which configuration
surfaces a release has to cover before it can claim anything).

## Why the repository exists

The Dotmac Observer host runs the observability stack from
`/opt/observability`: Prometheus, Alertmanager, Grafana and Loki. Its
Prometheus and Alertmanager configuration had no version-controlled owner.
`prometheus.yml` and `alerts.yml` were single-file bind mounts edited in place
on the host, and the only edit gesture that survived was `cat >>` appending to
the existing file, because a single-file bind mount is bound to an inode: a
`sed -i` or an `mv` writes a new inode and the running container keeps reading
the old one, so the edit appears to work and changes nothing until somebody
recreates the container.

An append-only, unattributed, non-atomic edit path cannot fail a promotion
gate, because there is no promotion. The observable consequence is the one this
repository was created to remove: central Prometheus scrapes ERP while loading
none of ERP's rendered alert rules, and nothing anywhere reports the
disagreement.

Two structural conclusions follow, and they are the whole design. Configuration
must be produced from reviewed inputs rather than typed at a host prompt
(`render.py`), and it must be activated as a whole directory rather than
patched file by file (`_compose` mounts `${OBSERVABILITY_RELEASE}/prometheus`,
not `${OBSERVABILITY_RELEASE}/prometheus/prometheus.yml`).

## Ownership

| Owner | Decides |
| --- | --- |
| Product / module | What a metric means, and what condition is worth alerting on |
| Product assembly | The metrics exporter, and the product's own rule bundle as a published artifact |
| `dotmac-deployment-foundation` (in `dotmac_starter_mt`) | Reusable rendering, conformance and promotion mechanics |
| **`dotmac_observability`** | Which bundle is accepted, what is scraped, how the evaluators are configured, who is paged, and how a release reaches the host |
| OpenBao | Secret values |
| `dotmac_governance` | Cross-repository engineering standards |

### Assembly is not authorship

The failure mode this boundary exists to prevent is small and attractive: once
a repository owns the evaluator, changing a threshold centrally is one line,
and it silently moves a product decision out of the product. The product's own
tests then prove something the fleet no longer runs, and the next product
release quietly reverts the central "fix" or fails to.

So this repository pins and assembles. It never authors a product alert
expression and never edits a fetched bundle: if a rule is wrong, the product
repository publishes a new bundle and the pin moves. The only expressions it
may own are its own control-plane meta-alerts (deadman, evaluator health,
bundle-digest mismatch), which it owns because no product is in a position to
observe them. See `AGENTS.md` §"The line this repository must not cross" for
the canonical statement and rule 5 for its enforcement status.

## Inputs

The typed desired state is assembled from a fixed set of documents, located by
`validate._inventory_files`:

| Path | Contract | Becomes |
| --- | --- | --- |
| `inventory/control-plane.toml` | `contracts/control-plane.schema.json` | `model.ControlPlane` |
| `inventory/targets/*.toml` | `contracts/target.schema.json`, `kind = "targets"` | `model.TargetSet` |
| `inventory/federations/*.toml` | `contracts/target.schema.json`, `kind = "federation"` | `model.Federation` |
| `routing/receivers.toml` | `contracts/routing.schema.json`, `kind = "receivers"` | `model.Receiver` |
| `routing/policies.toml` | `contracts/routing.schema.json`, `kind = "policies"` | `model.RouteDefaults`, `model.Route` |
| `routing/inhibition.toml` | `contracts/routing.schema.json`, `kind = "inhibition"` | `model.Inhibition` |
| `bundles/` | `contracts/bundle-lock.schema.json` | nothing yet; loading arrives in PR 3C |
| `inventory/supersessions/*.toml` | `contracts/supersession-request.schema.json` | `model`-free: a reviewed instruction consumed by the supersession workflow, never by a render |

And one input that is deliberately NOT in this repository:

| Supplied at | Contract | Becomes |
| --- | --- | --- |
| promotion time, from a private source | `contracts/private-inventory.schema.json` | `model.PrivateInventory` |

That row is the whole of ADR-0004 and ADR-0006 in one line. Everything above it
is a logical description; the resolution arrives separately, is validated
against a public schema, and is recorded in the receipt by digest rather than
by value. The only instance in Git is the synthetic fixture CI renders against
(`tests/fixtures/reference/private/`), whose safety is a checked property of
its content rather than of its location.

The directory globs are `sorted()`, not raw `Path.glob`. Glob yields in
directory order, which differs between filesystems and changes when a file is
rewritten; unsorted inputs would make the rendered bytes depend on where the
checkout happens to live, and the byte gate would fail for reasons no reviewer
could act on.

A document's `kind` is checked, never inferred from the directory it sits in
(`load` emits a `KIND` finding for a file under `inventory/federations` that
does not declare `kind = "federation"`). Placement is a convention; the
discriminator is the contract.

Every collection on `model.DesiredState` is a tuple in declaration order and
every record is a frozen dataclass. That is not tidiness. The renderer, the
semantic gates and (from PR 6) the drift comparison all read the same object,
so if any of them could mutate it, "the desired state" would depend on the
order the callers ran in and the byte gate would be checking a moving target.

## Three-layer validation

`validate.py` is deliberately three layers, and the separation is load-bearing.

**Schema** (`contracts/*.schema.json`, JSON Schema 2020-12, run through
`jsonschema.Draft202012Validator`) decides whether a document is well-formed.
Shape questions live here so a malformed file fails identically for every
reader, including a reader that is not this Python package. Errors are sorted
by `absolute_path` so two runs over the same broken file report in the same
order; an unstable error list makes a CI diff unreadable. Both multi-kind
contracts branch with `if`/`then` on `kind` rather than `oneOf`, because
`oneOf` collapses every branch's errors into a single "not valid under any of
the given schemas" and tells an operator nothing about which field is wrong.

**Loading** turns a validated document into a frozen `model` record. Nothing is
constructed from an unvalidated document, which is the premise that makes the
casts in the loader safe and lets the model carry no defensive code for shapes
the schema already refused. Documented defaults for optional knobs
(`DEFAULT_SCRAPE_INTERVAL`, `DEFAULT_SCRAPE_TIMEOUT`,
`DEFAULT_EVALUATION_INTERVAL`, `DEFAULT_RESOLVE_TIMEOUT`,
`DEFAULT_SECRETS_DIR`) live here once, rather than being spelled again in the
renderer where the two copies could drift.

**Semantics** (`semantic_findings`) answers the questions no single document
can, because they are about relationships between documents. A schema cannot
know that a route names a receiver that does not exist, that two products
claimed the same job name, or that an email receiver was declared while
`[smtp]` was not. The current gates:

| Code | Refuses |
| --- | --- |
| `RECEIVER-CHAT-ID` | A Telegram integration whose `destination` is not an integer chat id |
| `SMTP-UNCONFIGURED` | An email integration with no `[smtp]` block |
| `RECEIVER-NO-DESTINATION` | A non-webhook integration with no destination |
| `RECEIVER-SILENT` | A receiver with no integrations and no reviewed `null_policy` |
| `ROUTE-UNDECLARED` | A route or default naming a receiver `receivers.toml` does not declare |
| `ROUTE-DUPLICATE` | Two routes sharing an `id` |
| `RECEIVER-UNUSED` | A declared receiver no route or default reaches |
| `SEVERITY-UNROUTED` | No route matching `severity="warning"` or `severity="critical"` |
| `SEVERITY-UNDELIVERED` | A warning or critical route landing on a null receiver |
| `JOB-DUPLICATE` | Two scrape jobs, or a job and a federation, sharing a name |
| `TARGET-UNREACHABLE-EXPECTATION` | `expected` greater than the number of declared endpoints |
| `FEDERATION-PREFIX-COLLISION` | Two upstreams renaming into the same prefix |
| `CREDENTIAL-REF-SHARED` | Two integrations citing one credential, which cannot then be revoked for one of them |
| `METRICS-PATH-UNEXPLAINED` | A non-default `metrics_path` with no `path_rationale` |
| `LISTEN-NOT-LOOPBACK` | An evaluator bound to something other than a loopback address |

Findings are returned, never raised one at a time. A gate that stops at the
first problem makes an operator re-run it once per mistake; `cli._report`
prints all of them and exits non-zero once. `InventoryError` carries the whole
tuple for the same reason.

Several of these codes exist because the failure they describe is invisible in
production. A Telegram chat id quoted as a string is rejected by Alertmanager
at config load and presents as a receiver that simply never delivers; nothing
fires to tell anyone notifications broke. `TARGET-UNREACHABLE-EXPECTATION`
guards the same class of silence from the other end: a job that resolves to
zero targets produces no failures and no series, and is indistinguishable, to
every alert written over it, from a healthy system.

**Resolution** (`resolution_findings`) is the fourth layer, and it exists
because ADR-0004 put half the inputs somewhere else. It is not a fourth KIND of
question — it is the same cross-document question asked across the
public/private boundary — but its input is separate, so it is separate. The
public gates run for any reader of a checkout; these need material a public
reader does not have.

| Code | Refuses |
| --- | --- |
| `RESOLUTION-ENVIRONMENT` | An inventory for a different environment than the control plane declares |
| `RESOLUTION-HOST` | An inventory binding a different host |
| `RESOLUTION-MISSING` | A `target_id` or `credential_ref` with no binding, and no reviewed publication |
| `RESOLUTION-UNUSED` | A binding nothing reaches |
| `AUTHENTICATION-MISMATCH` | A declared capability the binding contradicts, in either direction |
| `PUBLICATION-SHADOWED` | A target carrying both a reviewed publication and a private binding |
| `TARGET-UNREACHABLE-EXPECTATION` | `expected` greater than the RESOLVED endpoint count |
| `RECEIVER-CHAT-ID` | A Telegram binding whose destination is not an integer chat id |
| `RECEIVER-NO-DESTINATION` | A non-webhook binding with no destination |

The last three moved here from the public layer with the values they read. What
a public reader loses is the check, not the guarantee: a promotion supplies the
inventory and cannot skip it.

`RESOLUTION-UNUSED` is the one most easily left out and the one that earns its
place. A binding nothing points at is a resolved endpoint nobody is looking
at — the exact shape of the CRM scrape job that outlived its product on the
Observer host by weeks (`docs/inventories/observer-as-built.md` §12). Checking
only that every public target resolves would have said nothing about it.

## Rendering

`render.render_control_plane` is the single authority for what the control
plane's configuration bytes are. Everything else, the CLI included, is an
adapter that calls it and writes or compares the result.

Since ADR-0006 it takes TWO arguments: the public desired state and a
`model.Resolution` joining it to one private inventory. The second is required
rather than optional, because a render without it would be a render of a
control plane that scrapes nothing, and a signature permitting that invites a
caller to produce one. Every lookup it performs was proved to succeed by
`validate.resolve` before the `Resolution` existed, so the renderer indexes
without guarding.

It returns the whole tree in one fixed-order call:

```
prometheus/prometheus.yml
alertmanager/alertmanager.yml
docker-compose.yml
```

Wholeness is a rule, not a convenience. A renderer that emitted one file per
call would invite a caller to update two of three and stage a configuration
nobody has ever seen.

### Dependency-free, hand-emitted YAML

`yaml_emit.py` is a hand-written emitter for the small closed subset of YAML
the control plane needs: nested mappings, sequences, scalars. It exists because
`AGENTS.md` rule 13 promises the same bytes on any machine, and a general YAML
library cannot promise that across versions. Quoting style, key ordering, line
width and flow-versus-block choices are implementation details of the library,
free to change in a minor release, and a rendered-bytes gate that fails because
a dependency moved teaches everyone to stop trusting the gate.

Every choice is therefore fixed in the open in that module: two-space indent,
block style except for the empty collections `{}` and `[]` which have no block
spelling, insertion order preserved and never sorted, a trailing newline, no
trailing whitespace, and one quoting rule applied uniformly. A scalar is
emitted plain only when it matches `^[A-Za-z_][A-Za-z0-9_.-]*$`, is not a YAML
reserved word, and does not parse as a float; everything else is
double-quoted. "Sometimes quoted" is a diff nobody can review, and an unquoted
`15s` today is an unquoted `1e5` tomorrow. `bool` is checked before `int`
because `bool` is an `int` in Python and `true` would otherwise render as `1`.

This module is not a YAML implementation and does not aim to be. Its job is
stability; the oracle for correctness is `promtool check config`, `promtool
check rules` and `amtool check-config`, which the promotion receipt contract
already reserves fields for (`validation.promtool_config`,
`validation.promtool_rules`, `validation.amtool_config`,
`validation.compose_config`). They are not part of `make check`, which stays
offline and dependency-light; CI's `config-validation` job fetches a pinned
toolchain and runs all three, plus `docker compose config`, against the
rendered reference fixture.

`jsonschema` is the only runtime dependency, and it validates rather than
renders: its output is a pass or a fail, not bytes anyone commits, so a version
change cannot move a committed artifact.

### A production render is not committed

The consequence of the split that surprises people. Public inputs plus the
public contracts render the SYNTHETIC fixture and nothing else; a production
render needs the private inventory and produces bytes that legitimately contain
resolved endpoints and credential basenames. It is produced at promotion time,
hashed, and recorded by digest — never committed.

`deploy/rendered/` is consequently empty in Git and stays that way, and `make
render-check` compares the reference fixture's committed bytes against a fresh
render of the same synthetic inputs. That is exactly as strong a determinism
gate as before: determinism is a property of the renderer and its inputs, not
of whether those inputs are real.

### Two digests over a private inventory, and why

`load_private_inventory` computes both, and the pair is what makes a
supersession checkable.

`digest` is over the whole canonical document and is the RECORD's identity —
what a receipt or a plan binds, and what a read-back is compared against.

`content_digest` is the same hash with `version` removed, and is the
ENVIRONMENT's identity. Two versions sharing it describe the same estate and
differ only in numbering.

The second is not a convenience. A supersession must refuse a version bump that
changes nothing, and a comparison of full digests cannot detect one at all,
because incrementing the version is itself a change to the bytes. That check
was written first against full digests, was dead code, and was found by the
test rather than by review — which is the argument for the test, and for
recording the shape here.

### Digest over paths and contents

`tree_digest` hashes each rendered path, a NUL, its contents, and another NUL,
in the render's fixed order. Both halves matter: a render that moved a file
without changing a byte inside it is still a different deployment, and a digest
over contents alone would call the two identical. This digest is what the
promotion receipt records as `rendered_digest`.

`differences` reports three conditions against the committed tree: `missing`,
`differs`, and `unexpected`. The third is the one that is easy to omit and
matters most, because a stale file left behind in the release directory still
gets mounted into the evaluator.

### Fixed paths inside the containers

`_PROMETHEUS_ETC = /etc/prometheus` and `_ALERTMANAGER_ETC = /etc/alertmanager`
are module constants, and so are everything derived from them:

| Constant | Value |
| --- | --- |
| `_RULES_GLOB` | `/etc/prometheus/rules/*.yml` |
| `_TEMPLATES_GLOB` | `/etc/alertmanager/templates/*.tmpl` |
| `_PROMETHEUS_SECRETS` | `/etc/prometheus/secrets` |
| `_ALERTMANAGER_SECRETS` | `/etc/alertmanager/secrets` |

These are not knobs, and `AGENTS.md` rule 14 does not ask them to be. Rule 14
governs environment-specific values: what the host is, which port is published,
how long retention runs, where the release lives. A path inside a container the
same renderer also writes the mount for is not environment-specific; it is an
internal joint between two lines of the same output. Making it configurable
would let the config file and the volume mount disagree, and that disagreement
is unobservable until an evaluator starts with no rules loaded, which is
precisely the failure that produced this repository.

The same reasoning drives the secrets constants. One host directory is mounted
into both containers at a different path in each, and the credential reference
in each rendered config is derived from the same constant that renders that
container's mount. A hand-written credential path can point into the other
service's tree, which renders and validates cleanly and then delivers nothing.

`rule_files` is a glob over the release's `rules/` directory rather than a
list of files, because the staged release already decides which bundles are
present and a hand-kept list here would be a second, silently divergent answer
to that question. Nothing populates `rules/` or `templates/` today; bundle
assembly is PR 3 and `templates/alertmanager/` is empty.

### Directory mounts, read-only

Both services mount `${OBSERVABILITY_RELEASE:?release directory is required}/<service>`
as a directory, `:ro`, plus the shared secrets directory, also `:ro`, plus a
named data volume. `OBSERVABILITY_RELEASE` is the one variable with `:?` rather
than a default, because a compose file that silently starts against the wrong
release is worse than one that refuses to start.

Directory mounts are the direct answer to the inode hazard described above. A
release is a directory; activation swaps the pointer the mount resolves
through; the container sees a whole consistent tree or the previous whole
consistent tree, never a half-applied one. Single-file mounts are how the
Observer host became append-only by hand.

Images are pinned by digest (`image@sha256:...`), never by tag, because a
receipt must be able to say exactly what ran, and `version` on
`model.Evaluator` is human evidence for the receipt rather than an identity.
Prometheus runs with `--web.enable-lifecycle` so activation can reload over the
lifecycle API without recreating the container and losing the scrape window.

The rendered compose declares exactly the two services this repository owns,
under the project name `observability-<environment>`. Grafana and Loki run on
the Observer host and are not rendered here; PR 2's read-only census records
what is actually there before PR 3 writes any production inventory.

### Federation renaming

`AGENTS.md` rule 9 is enforced in the renderer, not by convention.
`model.Federation.rename_prefix` is mandatory, and `_federation_config` always
emits a `metric_relabel_configs` entry rewriting `(up|scrape_.+)` to
`<prefix>${1}`. Imported `up` and `scrape_*` series describe the upstream's
opinion of its own targets. Left under their original names they join this
plane's health series, and a central `up == 0` then pages on a target this
plane neither owns nor can repair. Renaming makes the two populations
impossible to conflate in a query, which is a stronger guarantee than tuning
the rule to exclude them. `FEDERATION-PREFIX-COLLISION` stops two upstreams
renaming into one namespace and reintroducing exactly the confusion the rule
removes. The federation scrape also sets `honor_labels: true`: this plane is
importing the upstream's view, not relabelling it into its own.

## The exposure model

Every published surface declares two things, and both are mandatory with no
default: an **exposure** and an **address family**. ADR-0005 records the
decision and the measured finding behind it
(`docs/inventories/observer-as-built.md` §9.1); `AGENTS.md` rule 19 states it
as a hard rule. None of it is enforced here yet — the guard ships with the
Foundation release, not with a pull request in this repository.

### Owned elsewhere, adopted here

The vocabulary, its validation, its deterministic Compose and Nginx rendering,
its conformance suite and its rehearsal belong to
`dotmac-deployment-foundation`'s `IngressPolicy.v1`, in `dotmac_starter_mt`.
Nginx is the first provider and is not part of the contract; a second provider
must be addable without changing it. `dotmac_observability` is the first
adopter and owns a narrower thing: which surfaces are declared, with what
exposure and which families, and the promotion, receipt, rollback and drift
behaviour that carries those declarations to the Observer host. The resolved
addresses, ports, certificates and credentials live in OpenBao. The kernel and
the stateful modules own none of this.

The contract is wider than the two fields described below — it also carries
source policy, connection and body limits, timeouts, rate limiting, health
checking, telemetry, rollback semantics and the bindings that resolve private
promotion material into a listener. Those are consumed here, not specified
here. The values named below are the shape this repository needs; the
authoritative spellings arrive with the Foundation release.

### The two vocabularies

| Exposure | Means | Renders as |
| --- | --- | --- |
| `none` | Not published | No `ports` entry at all. Reachable only on the container network, by container name. |
| `loopback` | Published on loopback only | One explicit loopback bind per declared family. |
| `ingress` | Reachable only through the authenticated ingress | No host publish for the service. The ingress declares it as an upstream on the container network. |
| `public` | Published beyond the host | An explicit bind per declared family, and only alongside a reviewed exception block and a declared authentication requirement. |

| Address family | Renders as |
| --- | --- |
| `ipv4` | One IPv4 bind |
| `ipv6` | One IPv6 bind |
| `dual_stack` | One bind per family, each written out |

Prometheus, Alertmanager, node-exporter, cAdvisor and raw Loki are
internal-only. Loki ingestion is `ingress`, `dual_stack`, authenticated per
shipper. Nothing here is `public`.

### Why the family is declared rather than inferred

A short-form Compose publish, `PORT:PORT`, names no bind address. The daemon
binds the wildcard on both families and runs one `docker-proxy` per family, so
a document that mentions one number produces two listeners. On the Observer
host the IPv6 listener that appeared this way was covered by rules in the
`ip6tables` `DOCKER-USER` chain, which is jumped only from `FORWARD`; because
`docker-proxy` terminates the connection locally, the traffic arrives on
`INPUT` and never passes through that chain. Every one of those rules has a
zero packet counter.

Inferring the family from a bind address would reproduce the defect one layer
up: the renderer would guess, and the guess would be right or wrong with
nothing to compare it against. A declared family is a reviewable statement made
before anything renders, and — the property that matters most — it is something
conformance can hold a running stack to. The suite compares the listeners the
stack actually opens against the families the policy declared, which is the
check that would have caught the finding when it was made rather than a
fortnight later.

Rendering is therefore explicit in both directions. Short-form publishes do not
appear in the output, and a short form present in any input is a hard failure.
So is an undeclared family, an unauthenticated `public` surface, a backend that
declares `ingress` while also publishing a host port, and a `if loki` or
`if nginx` branch in the shared facility.

### Where the ingress sits

Between every remote sender and every service. It terminates TLS on 443, is
dual-stack capable, and requires per-shipper mTLS or per-shipper credentials
before a request reaches an upstream. A service behind it publishes no host
port of its own and is addressed on the container network. This is the only
mechanism by which a service in this control plane becomes externally
reachable; there is no second path.

Per-shipper credentials are what an address allowlist cannot provide. Six log
shippers means six credentials, one revocable without disturbing the other
five, and every accepted write attributable to the sender that made it.

### Which input supplies what

The split is ADR-0004's, applied to the fields this model adds.

| Public specification | Private resolution |
| --- | --- |
| Logical surface name | Resolved bind address |
| Exposure value | Port |
| Address family | DNS records, AAAA included |
| Authentication requirement, and the reviewed exception block for a `public` surface | TLS and server identity, certificate material |
| Protocol | Per-shipper credential bindings |

A declaration that a surface is `dual_stack` and authenticated is a public
fact: it describes a posture, and publishing it lets a reviewer disagree with
it. The addresses that declaration resolves to are not, and they never enter
this repository in any form.

## Secrets

Nothing in this repository holds a secret value, and nothing in it dereferences
one. `model.SecretFile` carries two strings, `openbao_path` and `file_name`,
both of which are safe to commit. The renderer turns the second into a path
under the appropriate secrets constant and emits `bearer_token_file`,
`bot_token_file`, `auth_password_file`, `url_file` or `api_url_file` depending
on the integration kind. Placing the file is a deployment act; the value is
host state sourced from OpenBao. `docs/SECURITY.md` holds the full posture,
including the shape-based scanner and its two exclusions.

## Promotion

Promotion is a state machine. No stage is skippable and every stage before
`ACCEPTED` rolls back to the exact preceding release:

| State | Means |
| --- | --- |
| `FETCHED` | Every pinned bundle artifact has been retrieved |
| `VALIDATED` | Digests match the lock, the inventory validates, the render is byte-identical, the secret scan is clean, and the evaluator tools accept the configuration |
| `REHEARSED` | The whole release was applied to a disposable host and verified there |
| `STAGED` | The immutable release directory exists on the target and the previous release pointer has been captured |
| `RELOADED` | The evaluators have taken the new configuration |
| `VERIFIED` | Targets are up to their declared `expected` count, rules exist and evaluate healthily, routes resolve, and the canary was delivered at the receiver |
| `ACCEPTED` | The receipt is written and the release is the new rollback target |

Two properties of `VERIFIED` are worth stating separately, because both are
easy to get wrong in a way that passes. "Rule inactive" is not recovery
evidence: a deleted rule, a failed evaluation and a vanished target all present
as "not firing", so verification counts rules that exist and evaluate cleanly
(`live.rules_healthy` in the receipt contract) and never treats absence as
health. And canary delivery is proved at the receiver, not at Alertmanager's
outbound attempt, because a 200 from a delivery API is not evidence a human can
be reached (`canary.delivered`).

`release.previous` in the receipt may be null only on the very first
promotion. Any later null means the rollback target was not captured, which
invalidates the rollback guarantee, so it is a receipt worth refusing.

A receipt is written for a failed or rolled-back promotion too
(`outcome: accepted | rolled-back | failed`): a promotion that leaves no record
is indistinguishable from one that never ran.

### The executor, and the facility it drives

`promote.promote` is the state machine above. It owns the ORDER, the refusals,
the rollback decision and the receipt; it owns no host effect at all. Every one
of those is a method on `promote.PromotionFacility`, a Protocol this repository
DECLARES and does not implement, because reaching a host belongs to
`dotmac-deployment-foundation` (see the ownership table above). A control plane
that grew its own transport would be a second answer to how a release reaches a
host, and the second answer is the one that never gets the fixes.

The split is also what makes the machine testable. Every stage, every refusal
and every rollback path is exercised against a recording double in
`tests/unit/test_promotion_executor.py`, with no host, container or daemon —
so "no stage is skippable" and "a failure after staging rolls back" are
properties with tests rather than sentences in this file.

Two refusals happen before anything is fetched. The target host is NAMED by the
caller and merely CHECKED against the inventory (`AGENTS.md` rule 17: never
inferred from an inventory row), and the revision arrives as an
`AssertedRevision` carrying an external oracle reference, because "this commit
is the protected-main tip" is not a repository-local fact (rule 3, Governance
ADR 0013).

Rollback begins at `STAGED` and not before. Before `STAGED` nothing on the host
has changed, so a fetch or validation failure leaves the previous release
running untouched and invoking a restore there would be a host mutation in
response to a failure that caused none. From `STAGED` onward every failure —
including a failure at `ACCEPTED` — restores the pointer captured at staging.
A restore counts only when the facility returns a READ-BACK proving it: a
`rollback()` that returns without raising says a command succeeded, and only an
observation says the host came back.

**What is still missing is the facility.** The Foundation's shipped executor
swaps a Compose image digest on the local host; it stages no release directory,
captures no previous pointer from the host, has no remote transport and reads
nothing back from Prometheus or Alertmanager. `docs/adr/0010-the-promotion-executor-and-the-facility-contract.md`
states, as a contract another lane can implement, exactly what it must provide.

The rehearsal is held to conditions 1, 2, 4 and 5 only, and the exclusion is
stated rather than silent: a disposable host's ingestion counter starts at zero,
which is the state `INTEGRITY-BASELINE-ZERO` refuses, and its first release has
no rollback target. Applying the production conjunction to a rehearsal would
make the rehearsal permanently unpassable, which teaches a lane to skip it.

## Three independently comparable artifacts

Drift is detectable only because three descriptions of the same control plane
exist and can be read separately:

1. **Desired state** — this repository at an exact commit, loaded into one
   `model.DesiredState` and rendered to a known `tree_digest`.
2. **Live state** — read back from the Prometheus and Alertmanager HTTP APIs:
   targets and their health, loaded rules and their evaluation state, the
   resolved route tree.
3. **Last verified receipt** — the record of what the last accepted promotion
   actually proved, including `rendered_digest`, the bundle set, the release
   pointer and the live counts at the time.

Any pair can disagree, and each disagreement means something different. Desired
against live is unpromoted change or a host edit. Live against receipt is
something that changed after acceptance without going through promotion.
Receipt against desired is a promotion that never happened. A design that can
only read one of the three cannot detect drift at all, which is why
`DesiredState` is a single value rather than a habit of reading files in the
right order, and why the receipt is a contract rather than a log line.

All three are artifacts now. The third used to be a procedure — read these
APIs, in this order — which cannot be compared later, attached to a ticket or
replayed against a different desired state; it is
`contracts/live-observation.schema.json`, and every field in it is a count, a
boolean, a digest, an enum, a logical name or a timestamp. There is
deliberately no field an endpoint, a scrape URL, a credential basename or an
error string can be typed into: `last_error` carries the target's address in
most real failures, and one such field would undo rule 18 for the whole
document.

`drift.compare` reports which PAIR disagrees, because the pair is the
diagnosis. Handed fewer than three artifacts it reports `DRIFT-INCOMPARABLE`
and performs the pairs it can, rather than presenting a two-artifact answer as
a three-artifact one — a partial comparison labelled as a full one is worse
than no comparison, because a reader acts on it.

## Delivery train

| PR | Adds | State |
| --- | --- | --- |
| 1 | Governance (`AGENTS.md`, `docs/CONTROL_EXCEPTIONS.md`), the five contracts, the typed model, three-layer validation, the deterministic renderer and emitter, the CLI, the reference fixture with its committed rendered bytes, and the CI and sensitivity-proof work originally scheduled for PR 4 | **done, this change** |
| 2 | A read-only as-built census of the Observer host, written to `docs/inventories/observer-as-built.md` | blocked: requires Michael to name the Observer SSH target explicitly |
| 3A | Adoption of `IngressPolicy.v1`: declared exposure and address family on every published surface, the Loki-ingestion selection, and the removal of short-form publishes from the rendered output. The contract, its rendering and its conformance suite are `dotmac-deployment-foundation`'s, so this lane is blocked on that release (ADR-0005) | planned |
| 3B | The ADR-0004 split in the contracts (ADR-0006): logical `target_id`, the ObserverInventoryV1 contract and its canonical digest, the per-target publication block, the inverted `openbao_path` check, the resolution layer, and the private-material scanner | **done** |
| 3D | The rest of the controller-owned release boundary (ADR-0007): Grafana provisioning and dashboards, Loki, promtail and collector configuration, each with its own contract, fixture, committed render and acceptance oracle | planned |
| 3C | Real production inventory under `inventory/`, bundle locks under `bundles/`, and `bundle.py` (fetch and digest-verify) | planned |

> **Two sequences, one plan.** The lanes above are this repository's own work.
> They sit inside a wider cross-repository train for the ingress facility,
> which runs: a product-first ingress census and extraction dossier; a
> Foundation contract/model/validation change; a Foundation Nginx provider and
> dual-stack rehearsal; an immutable Foundation release; a pin-only adoption
> here; a policy and configuration change here; a disposable rehearsal of IPv4,
> IPv6, authentication, rotation and rollback; and finally an explicitly
> authorized production cutover. Lane 3A is where the last four of those touch
> this repository, and it decomposes into the pin-only adoption and the policy
> change rather than landing as one commit. Neither sequence supersedes the
> other: one describes what changes here, the other what has to exist first.
| 4 | CI workflows, the standards-profile pin, the architecture tests and the mutation-based sensitivity proofs | delivered early, in PR 1; the remaining proofs cover the capabilities the PR 3 stack and PR 5 add |
| 5 | Disposable-host rehearsal on the dedicated test server, and `live_verify.py` | `live_verify.py` **done**; the rehearsal needs the Foundation facility |
| 6 | The promotion facility in `dotmac-deployment-foundation` vNext, plus `receipt.py` and `drift.py` here | everything in THIS repository is **done** (`promote.py`, `receipt.py`, `drift.py`, `contracts/live-observation.schema.json`); the facility is not, and its contract is ADR-0010 |
| 7 | Production bootstrap of the Observer host | planned, separately authorized |
| 8 | ERP bundle onboarding: the first product bundle pinned, promoted and verified | planned |

PR 3 is a stack rather than a single change, and the order is a dependency
rather than a preference. 3A settles what may be published and to which
address families, 3B settles which fields of a target document are public at
all, and only then does 3C write a production inventory — because Git history
is not retractable and the first production inventory commit is the one that
cannot be corrected afterwards (ADR-0004). 3A is additionally gated on a
`dotmac-deployment-foundation` release carrying `IngressPolicy.v1`; nothing in
this repository defines that contract.

### What exists today

Everything under `src/dotmac_observability/` listed as shipped below, every
contract under `contracts/`, and the reference fixture at
`tests/fixtures/reference/` with its committed `rendered/` tree.

`make check` runs `poetry-lock-check`, `lint`, `format-check`, `type-check`,
`secret-scan`, `private-scan`, `schema-check`, `production-check`,
`render-check` and `test`, and the CI matrix names that list exactly.

The promotion lane — `promote.py`, `live_verify.py`, `receipt.py`, `drift.py`
and `contracts/live-observation.schema.json` — is complete AS FAR AS THIS
REPOSITORY'S SIDE GOES, and it cannot promote anything, because every host
effect belongs to `dotmac-deployment-foundation` and no version providing them
is installable. `.github/workflows/promote.yml` encodes the sequence and stops
at that step by construction: it probes for an installed facility rather than
carrying a comment saying one is missing, because a comment is removed by
whoever wants to try and a failing import is removed only by making it succeed.
ADR-0010 states what the facility must provide.

Two facts this repository cannot check, recorded rather than left implicit. The
receipt requires `images` to equal the approved plan's image set, and the
deployment control plane's plan record carries no image field — the images live
inside its opaque `spec` — so `authorized_images` is supplied by the promotion
caller and the comparison proves the caller consistent with itself. And there
is no read API for an approved plan there: no fetch-by-digest and no
verify-approved route, only a write path that compares an expected digest
during authorization. An Observability promotion is HANDED an authorization; it
cannot independently confirm one.

`render-check` and `schema-check` were scheduled for 3C, blocked on "no
production inventory to validate". ADR-0006 makes that block permanent — there
will never be one in the repository — so they point at the reference fixture
and run today rather than never.

Governance enforcement landed in the same change rather than in PR 4:
`tests/architecture/test_no_secret_material.py`,
`test_repository_contract.py` and `test_control_exceptions.py`, the
sensitivity proof at `tests/mutations/test_secret_detector_bites.py`, the
standards-profile pin at `.dotmac/standards-profile.json` (which names
`render.render_control_plane` and `validate.validate` as decision interfaces
and `model.py` as a typed contract surface, matching what those modules'
docstrings already claimed), and the two workflows
`.github/workflows/ci.yml` and
`.github/workflows/engineering-standards.yml`.

The register of regions that are unmonitored rather than exempt is
`docs/CONTROL_EXCEPTIONS.md`. Nine rules are declared unmonitored there today,
every one of them waiting on machinery the PR 3 stack, PR 5 or PR 6 adds. Read that file
before describing any rule as enforced: `AGENTS.md` marks each rule's
enforcement individually, and a rule carrying `none yet (PR n)` is stated
review discipline.

### Module by module

| Module | Responsibility | Status |
| --- | --- | --- |
| `model.py` | Frozen, ordered, fully typed desired state; one `DesiredState` value | shipped |
| `validate.py` | Schema layer, typed loading, cross-document semantic gates, shape-based secret scanner | shipped |
| `yaml_emit.py` | Deterministic block-YAML emitter for the subset the control plane needs | shipped |
| `render.py` | The three rendered files, `tree_digest`, `write_tree`, `differences` | shipped |
| `cli.py` | `validate`, `render [--check]`, `secret-scan`; thin adapters over the library | shipped |
| `bundle.py` | Fetch a pinned product bundle, verify its digests, assemble the release `rules/` tree | PR 3C |
| `validate.load_private_inventory` / `resolve` | Read and digest an ObserverInventoryV1 document, and join it to the public state with every lookup proved | shipped |
| `validate.supersede_findings` / `supersede_summary` | Prove one private document legitimately replaces a NAMED earlier version, and describe the change in logical names only | shipped |
| `validate.load_supersession_request` / `apply_supersession` | Apply a reviewed, public retirement request to a stored private document, preserving fields this package does not read | shipped |
| `validate.scan_for_private_material` | Refuse resolved material anywhere in the tracked tree (rule 18) | shipped |
| `live_verify.py` | Compare a read-back with the desired state: the six conditions of `AGENTS.md` rule 29, and the verdict they add up to. Performs no I/O — it takes a parsed observation | shipped |
| `receipt.py` | Build a promotion receipt from what was observed, and refuse one that claims more than it proved | shipped |
| `drift.py` | Three-way comparison of desired state, live state and the last verified receipt, grouped by which pair disagrees | shipped |
| `promote.py` | The promotion state machine, and the `PromotionFacility` Protocol the Foundation must implement. Declares every host effect and performs none | shipped |
