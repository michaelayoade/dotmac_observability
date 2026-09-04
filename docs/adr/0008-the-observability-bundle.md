# ADR-0008: One bundle, and the faults it makes unrepresentable

- **Status:** Accepted
- **Date:** 2026-08-30
- **Supersedes:** nothing
- **Amends:** `observability-target.v2` (two optional fields),
  `observability-supersession-request.v1` (a second `kind`)
- **Related:** `AGENTS.md` rules 1, 2, 13, 14, 15, 18, 19, 21;
  `docs/adr/0002`, `0004`, `0005`, `0006`, `0007`;
  `docs/inventories/observer-as-built.md` §§ 14–16

## Context

The renderer produced three files: a Prometheus config, an Alertmanager config
and a compose file. Everything else the Observer host runs — the log store, the
shipper, the dashboards, the syslog routing, the rotation, the timezone, the
firewall — was hand-maintained, and `/opt/observability` accumulated twenty-two
`.bak-*` files to prove it.

A measurement pass on 2026-08-30 found four faults. What matters about them is
not that they are four bugs; it is that **not one of them was in a file the
renderer produced**, and therefore not one of them could have been caught by
anything this repository already had.

**The mail facility had been dead for a month.** `/var/log` is
`root:syslog 0755`. rsyslog drops privilege to the `syslog` user. It was told to
write `/var/log/mail.log`, which did not exist, and a privilege-dropped writer
cannot create a file in a directory it has no write bit on. `action-5-builtin:omfile`
suspended and resumed **10,161 times in thirty days** (`journalctl -u rsyslog`,
30 days), with `file '/var/log/mail.log': open error: Permission denied` at
01:02 on 30 August and 01:40 on 23 August — the two weekly logrotate runs, which
HUP rsyslog and make it try to open the file again. `postfix@-.service` is
running, so the facility has a real writer and every one of its messages was
discarded.

**Alertmanager was gossiping with itself.** `/api/v2/status` reports exactly one
peer, which is its own name, and the log carries `dropping messages because too
many are queued  current=4097 limit=4096` every fifteen minutes for weeks.
Alertmanager clusters by default and binds its gossip port whether or not a peer
exists; nothing had declared this deployment a singleton, and an omission is not
a declaration.

**Eighteen of eighteen targets read green while 1,858,942 samples were
rejected.** `prometheus_target_scrapes_sample_duplicate_timestamp_total` stood
at 1,858,942 with every target `up`. Target health and ingestion integrity are
separate facts, and every check the fleet had read only the first.

**Seven IPv6 firewall rules were in a chain IPv6 never traverses.** `ip6tables
-S DOCKER-USER` carries DROP rules for 9090, 9093, 3100, 8080, 8000, 9100 and
8200. An IPv4 container publish is forwarded and therefore traverses
`DOCKER-USER`; an IPv6 one terminates on `INPUT`. Every port those rules name
reads as closed and is open.

The common shape is that each is a **seam between separately owned pieces**, and
a renderer that emits only the evaluators has no seam to check.

## Decision

### 1. One `ObservabilityBundleV1`, rendered whole

`contracts/bundle.schema.json` (`observability-bundle.v1`, declared in
`inventory/bundle.toml`) accounts for the log store, the shipper, dashboard
provisioning, the Observer-owned syslog and rotation contract, the declared
infrastructure timezone, the roster of owned resources, the retired-product
list, the exposure policy and the verification gates. `render_control_plane`
emits **seventeen** files in a fixed order, in one call, and `tree_digest`
covers all of them.

It is part of the same `DesiredState` rather than a second one because a
promotion that can activate the evaluators without the rotation contract and
the exposure policy is a promotion that can leave the host in a combination
nobody described.

### 2. The bundle holds no topology and no credentials

Unchanged from ADR-0004, and worth restating because the bundle is the first
document that was tempted. A firewall rule wants a source; a datasource wants a
URL. Neither is written here.

A source is a **named, typed set** — `management`, `tunnel_interface` — and what
it resolves to is a `source_set_binding` in the private inventory. A datasource
URL is derived either from a local rostered service or from a logical
`target_id` already owned by one public scrape job and resolved through the
private inventory. The datasource never carries an endpoint, and resolution
refuses an undeclared, authenticated, ambiguous, missing or multi-endpoint
target rather than choosing one by order. Resolution also checks source sets in
both directions and refuses a kind mismatch, which is a disagreement only the join can see: a set declared
`tunnel_interface` and bound to prefixes renders a source match where an
interface match was intended, and validates cleanly on both sides.

### 3. Each fault becomes a shape the contract cannot express

**Syslog.** The directory contract, the per-file owner/group/mode and the
rotation policy are declared. The renderer emits an rsyslog drop-in that
restates `$FileOwner`/`$FileGroup`/`$FileCreateMode` before **every** action
(rsyslog's directives are positional, which is how ownership drifts between
included files), a `systemd-tmpfiles` entry that creates each file **as root**
with the declared ownership, and a logrotate stanza with an explicit
`create <mode> <owner> <group>`, `su`, `delaycompress` and a `postrotate`
reopen.

The repair deliberately **does not widen the directory**. `/var/log` stays
`0755`; something other than the privilege-dropped writer creates the file. A
gate refuses a mode without owner write, a world-readable log file, a file
outside the declared directory, and two facilities writing one path with
independently declared ownership.

**Alertmanager.** `--cluster.listen-address=` is rendered unconditionally,
which disables clustering outright. Routing, receivers, inhibition and
templates are byte-identical to before — asserted, not claimed — because none
of them is a cluster concern. The only behaviour removed is notification
deduplication between peers, and there are none.

**Verification.** A gate carries **two** predicates, `health` and `integrity`,
and the renderer emits `(health) unless (integrity)` — the alert fires exactly
in the state a scrape-health check reports as green. A gate whose two
predicates are the same expression is refused, and so is an `integrity`
predicate that mentions no ingestion counter, which is a gate with one
predicate and a longer name.

**Exposure.** The chain is **derived** from the surface kind and the address
family, so an IPv6 rule cannot be written into `DOCKER-USER`. This is
`iptables` (`-i wg0`), not nftables' `iifname`, which has been carried across
from another host's ruleset once already.

**Timezone.** `infrastructure` is a `const: "UTC"` in the contract rather than a
gate, so a local zone is not a shape this repository can hold. `presentation`
reaches Grafana's provisioning and nothing else: rendering a local zone for a
reader is presentation, storing one is a data model.

### 4. Two amendments to `observability-target.v2`, both optional

`params` and `static_labels`. Both were named as gaps by
`docs/inventories/observer-as-built.md` §15, and both are omissions in the
accepted contract rather than in the stored capture.

`params` is classified the way `metrics_path` was: a parameter that selects an
exposition FORMAT is scrape protocol. Without it the OpenBao job scrapes JSON
rather than Prometheus exposition — a target that reads green and stores
nothing.

`static_labels` carries the as-built's logical instance labels. A logical name
is what the whole public half of ADR-0004 is made of; the risk it opens is
somebody typing a resolved address into a label value, and that is what the
private-material scan is for.

Both are **optional additions**, so every v2 document written before this
amendment is still a valid v2 document — which is why the version does not
move. A required field changing is a different contract; an optional field
appearing is the same contract answering a question it could not answer before.

**One residual gap, narrowed and not closed.** `static_labels` is per JOB. The
as-built gives each of node-exporter's four endpoints a *different* instance
label, and a per-endpoint label has to be paired with the endpoint, which lives
in the private inventory. The consequence is stated in
`inventory/targets/fleet-infrastructure.toml` so a drift comparison is not
quietly wrong: that one job is not byte-identical to the as-built, and the
difference is an unrepresentable label rather than a real change. Both candidate
repairs cost something a reviewer should choose between.

### 5. The capture format is readable, and migrating out of it is a reviewed change

The stored production inventory declares
`observability-private-inventory.v1 (PROPOSED)` — the shape PR #2's census
produced, three PRs before ADR-0006 accepted the contract. It yields 68 errors
against the accepted contract, and both mutation tools load the previous version
through that contract as their first act, so the supersession workflow fails at
its first tool step with an error list that reads like corruption, **after**
passing its own precondition guard.

Three changes:

`contracts/private-inventory-capture.schema.json` writes the old shape down.
Strict about keys — which the census recorded — and permissive about leaf types,
which it did not. A contract that invented the types would assert something
nobody measured.

`inventory-classify` reads one field and prints one line, with exit codes 0 / 2
/ 3 for accepted / capture / unrecognised, and `--expect` turns it into a gate.
The workflow runs it **before** anything loads the document. An unrecognised
third shape stays unrecognised rather than being sorted into whichever known
format it resembles: the two are migrated by different code, and being wrong
about which one holds a production estate is the risk.

`inventory-migrate` rewrites a capture into the accepted contract. **Every value
in the result comes from the store.** That is what makes this provisioning
without disclosure, and it is the only reason ADR-0006's boundary can hold while
the production document is unmigrated — the alternative was a human editing
OpenBao by hand.

The one field the capture does not hold is the host binding: the accepted
contract requires `host.identity` and `host.ssh_alias` and the capture has no
`host` key. It arrives as a **repository secret**, materialised into a mode-0600
file in the one step that needs it and shredded there — neither public Git nor a
CI input, which is exactly the distinction rule 21 draws. Adding a *target*
still has no path anywhere, because it needs a resolved endpoint that has never
been anywhere but the store.

The migration **refuses rather than guesses**: an unmappable credential, a
`tls_config` (dropping it would silently change how a live target is verified),
a receiver binding it cannot complete, a federation split the public inventory
disagrees with, an incomplete host binding.

**The compare-and-set consequence, stated because it looks like a bug.**
Migrating rewrites the document and therefore changes its digest, and the digest
is the CAS precondition. A request naming the pre-migration digest is refused
*after* the migration has run — correctly, but only after looking as though the
work had been done. The refusal message names `inventory-classify` as the way to
tell "already migrated" from "somebody else moved the store", which are the same
digest mismatch and different problems.

### 6. A retired product stays retired, as a standing property

`retired` declares products whose monitoring is gone, with every spelling they
were known by, and `retirement_findings` refuses a **rendered tree** that
mentions one.

Over rendered bytes rather than inventory documents, for two reasons. It covers
every surface the bundle produces rather than the subset somebody thought to
search. And it cannot read nothing: a sweep over a tree it failed to load
reports "no references" identically to a sweep over a clean one, whereas an
empty rendered tree would have failed the render first.

### 7. Amendment — 2026-09-04: remote datasources reuse target resolution

The live Selfcare dashboard datasource had an address typed directly into
Grafana and drifted to another product's VictoriaMetrics host. A remote
datasource now names the same logical `target_id` as its Prometheus scrape.
That scrape owns the public scheme, private inventory owns the single resolved
endpoint, and the datasource owns only its Grafana name and stable UID. This is
one endpoint decision with two consumers, not a second topology map.

Grafana also logs startup errors when the mounted provisioning root omits its
optional `plugins/` and `alerting/` directories. The rendered tree now emits a
valid empty provisioning document in each directory. A Grafana 13.0.1 image
probe accepted both documents without a provisioning error; placeholder files
were rejected because alerting warns on unsupported suffixes.

## Consequences

### The bundle deliberately does not carry

**Grafana dashboard JSON.** The provisioning surface is declared; no dashboard
is shipped. A 2026-08-30 read of `grafana/data/grafana.db` found **zero
dashboards of any kind**, so there is nothing to preserve — which also resolves
an item previously recorded as UNKNOWN. A future dashboard belongs in
`grafana/dashboards/` under a declared provider, not in the database.

**Prometheus alert rules for products.** Unchanged: rule 5 keeps them
product-owned. The bundle renders only the control-plane meta rules, which no
product can observe.

**Live image digests for the three new runtimes.** Loki, Promtail and Grafana
all float on `:latest` on the host and their running digests were not measured.
`inventory/bundle.toml` carries an obviously invalid all-zero digest rather than
a plausible wrong one, so a promotion **fails at pull time** instead of pulling
something. Measuring and pinning them is a prerequisite for Part C.

**The applied state of anything.** Every delta in `inventory/bundle.toml` is
marked. Declaring the loopback posture, UTC, and the SSH ingress policy does not
apply any of them; that is a Foundation promotion.

### What still cannot run

The supersession workflow cannot execute today, for three reasons that are
configuration rather than code and that only a repository administrator can
resolve: **no self-hosted runner is registered** (`actions/runners` returns
zero, so the job queues forever), **the `private-inventory` environment does not
exist** (`repos/.../environments` returns zero, so the human gate the workflow's
own comment describes is not in place), and **none of the OpenBao secrets it
reads is configured**. Recorded here rather than left implicit: until then the
only thing preventing an unapproved production write is the document failing to
load, which is an accident rather than a control.

## Alternatives considered

**Keep the host artefacts hand-maintained and only render the evaluators.**
Rejected: it is the status quo, and the status quo is twenty-two `.bak-*` files
and a facility that was dead for a month.

**Fix the mail.log failure by making `/var/log` group-writable.** Rejected. It
would work, and it would also let the log shipper's own writer create, rename
and unlink every other service's log. Having something else create the file
costs one tmpfiles line and grants nothing.

**Set `honor_timestamps: false` on the federation, or drop the duplicated
series.** Rejected explicitly, and not because it would not work — it would.
Both make the symptom invisible rather than absent: the samples would still be
wrong upstream and nothing would ever say so again. The ingestion-integrity gate
does the opposite, and the evidence goes to the owner.

**Narrow the federation's `match[]` to stop importing the colliding series.**
Rejected as a *fix* while remaining correct as hygiene. It would remove the
symptom from this plane and leave Sub with duplicate writers nobody had told
about. The narrowing decision is Sub's, as `inventory/federations/dotmac-sub.toml`
already records.

**A separate contract per concern — logging, dashboards, host.** Rejected. Three
documents is three things a promotion can activate a subset of, which is the
failure the single bundle exists to prevent.

**Migrate the stored inventory by hand, once, and move on.** Rejected. It is one
unversioned unreviewable write against production, and the tooling that would
have caught a mistake is the tooling being bypassed. The migration is longer to
build and is reviewable, repeatable and refusable.
