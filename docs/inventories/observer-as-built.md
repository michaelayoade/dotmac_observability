# Observer as-built census — 2026-08-29

A dated characterization of the observability control plane as it actually
runs. **Facts, not mandates** (see `docs/inventories/README.md`), and
deliberately not a plan: what should change about any of this is argued in an
ADR or a pull request, not here.

Method: read-only inspection over SSH, authorized by Michael and confined to
`docker inspect`, `docker image inspect`, `stat`, `find`, `sha256sum`, the
Prometheus and Alertmanager read APIs, and reading configuration files. No
container environment was printed, no credential value or secret-file content
was read, and **nothing on the host was changed**. The raw capture lives in an
ephemeral private workspace and is not committed.

Redaction follows ADR-0004. Resolved hostnames, addresses, complete scrape
URLs, credential-file bindings and federation endpoints are private promotion
material and appear only in the private inventory handed over separately. What
is below is structure, counts, versions, digests and health.

> **The host changed after this census ran.** A hand edit later on 2026-08-29
> removed the retired CRM product's configuration. §§1-11 are left exactly as
> measured, so every count in them is the pre-change count; **§12 records the
> delta and the post-change state**, and is what a cutover must reproduce.
> Read §12 before citing a number from §4, §5 or §7.

## 1. Platform and project identity

| Fact | Value |
| --- | --- |
| Docker | 29.4.3 (build 055a478) |
| Compose | v5.1.3 |
| Compose project | `observability`, from `/opt/observability/docker-compose.yml` |
| Services in the project | 9 — prometheus, alertmanager, grafana, loki, promtail, node-exporter, cadvisor, glitchtip, glitchtip-worker |
| Version control on `/opt/observability` | **none** — no `.git`, no remote, no history |

The host also runs eight unrelated Compose projects, including roughly sixty
exited test containers and eleven test PostgreSQL instances. That is outside
this repository's scope but bears on capacity (§7) and on the standing rule
that Observer is not a test host.

## 2. Running images

Every observability image is tagged `:latest`. None is pinned by digest. The
digests below are what was *actually running* at census time and are the only
thing that identifies these deployments; the tag does not.

| Service | Image ref | Running digest | Image built |
| --- | --- | --- | --- |
| prometheus | `prom/prometheus:latest` | `sha256:e4254400b856…6146acc3` | 2026-04-27 |
| alertmanager | `prom/alertmanager:latest` | `sha256:51a825c2a40a…47a4d286` | 2026-04-29 |
| grafana | `grafana/grafana:latest` | `sha256:0f86bada30d6…78a4a73a` | 2026-04-17 |
| loki | `grafana/loki:latest` | `sha256:73e905b51a7f…cc0dc8eb4` | 2026-03-26 |
| promtail | `grafana/promtail:latest` | `sha256:6cfa64ec432b…dd7241381` | 2026-03-25 |
| node-exporter | `prom/node-exporter:latest` | `sha256:e9cff4fc67b1…1b357205` | 2026-04-07 |
| cadvisor | `gcr.io/cadvisor/cadvisor:latest` | `sha256:3de2bd520312…6f44ec57` | 2025-12-25 |

Binary versions reported by the running processes: **Prometheus 3.11.3**,
**Alertmanager 0.32.1**.

> This repository's CI pins `promtool` 3.2.1 and `amtool` 0.28.0 for its
> config-acceptance job. Those are older than what production runs, so CI
> currently proves the rendered configuration is accepted by a *different*
> version than the one that would load it. Aligning the pins is PR 3 work.

Container users: prometheus and alertmanager run as `nobody`, grafana as 472,
loki as 10001. **promtail and cadvisor run as root**, both with host mounts.

## 3. Configuration mounts — the inode constraint, measured

| Path | Mounted at | Mode | Inode | Links | RO? |
| --- | --- | --- | --- | --- | --- |
| `prometheus/prometheus.yml` | `/etc/prometheus/prometheus.yml` | 644 | 524424 | 1 | **no** |
| `prometheus/alerts.yml` | `/etc/prometheus/alerts.yml` | 644 | 524425 | 1 | **no** |
| `alertmanager/alertmanager.yml` | `/etc/alertmanager/alertmanager.yml` | 644 | 524428 | 1 | **no** |
| secrets directory | *(redacted — ADR-0004)* | dir | — | — | yes |
| one Alertmanager credential file | *(redacted — ADR-0004)* | 600 | — | — | yes |

Three configuration files are **single-file bind mounts**, each with one link,
and each mounted **read-write** into its container. This is the mechanism
ADR-0001 and ADR-0002 describe, now confirmed on the host: a bind mount binds
an inode, so any editor that writes a replacement file detaches it and the
container keeps reading the old content while the edit appears to succeed. The
only safe gesture is appending in place.

One Alertmanager credential is likewise a single-**file** mount, so the same
hazard applies to rotating it, not merely to editing configuration. Its source
and container paths are a credential-file binding and therefore private
material under ADR-0004; they are in the private inventory, not here.

## 4. Prometheus

- `global`: `scrape_interval: 15s`, `evaluation_interval: 15s`.
- `external_labels`: **empty**. This evaluator stamps nothing on its own
  series, so nothing distinguishes them by environment or control plane.
- `rule_files`: **a single file**, `/etc/prometheus/alerts.yml` — not a
  directory glob. There is no per-product rule file and no place to drop one.
- `alerting`: one Alertmanager, one static target.
- 16 scrape jobs; 19 active targets; 0 dropped.
- Flags: `--web.enable-lifecycle` (so `POST /-/reload` works),
  `--web.enable-remote-write-receiver`, retention `30d`.

Credentials on the seven authenticated jobs are all
`authorization: {type, credentials_file}`. **No inline credential appears in
`prometheus.yml`** — checked explicitly.

> This repository's renderer emits `bearer_token_file`, which is the older
> spelling of the same thing. Reproducing the as-built byte-for-byte needs the
> `authorization` block. PR 3.

The federation job's relabelling is, in shape, exactly what this repository's
rule 9 requires and what its renderer already emits:
`source_labels: [__name__]`, `regex: (up|scrape_.+)`, `target_label: __name__`,
`replacement: federated_${1}`, with `honor_labels: true`. This is the one part
of the as-built the design already matches.

### Target health

18 of 19 targets up. One down: **`dotmac-crm-app`, HTTP 502** — a scrape job
for a product that has been retired. It is not merely stale configuration: it
is currently firing `ServiceDown`, so a decommissioned system is generating
live pages.

## 5. Rules

56 alerting rules in 9 groups. **Zero recording rules.** All 56 report
`health: ok`. Five are firing at census time.

| Group | Rules |
| --- | --- |
| `prepaid_enforcement` | 13 |
| `dotmac_identity_plane` | 10 |
| `billing_health` | 7 |
| `dotmac_academy` | 6 |
| `host_alerts` | 5 |
| `dotmac_sub` | 5 |
| `dotmac_omni` | 4 |
| `claude-knowledge` | 3 |
| `dotmac_erp` | 3 |

Severity split: 33 `warning`, 23 `critical`. No duplicate alert names. Every
rule carries a `severity` label and a `summary` annotation.

**Operational runbook coverage is 0 of 56.** 53 rules carry no `runbook_url`
at all. The remaining three carry one, but it links to an error-tracker issue
query — a place to look, not a procedure to follow — so no rule on this host
puts a responder in front of instructions. Rule 8 requires a runbook on every
rule; the as-built satisfies it zero times.

Separately, 14 rules carry a `runbook` annotation that Alertmanager never
renders, so it reaches nobody.

### The ERP gap, stated precisely

The `dotmac_erp` group holds three hand-written application rules —
`ErpHighErrorRate`, `ErpSlowRequests`, `ErpLokiLogsDropping`. **None of them
comes from ERP's rendered Deployment Foundation alert bundle.** So the summary
"central Prometheus scrapes ERP while loading none of its rendered alert
rules" is accurate: ERP is scraped, three unrelated rules about ERP exist, and
the rendered bundle is absent.

The `dotmac_omni` group holds four **CRM** rules, one of them `critical`, for
the same retired product as the dead scrape job.

## 6. Alertmanager

- One receiver, `default`, with a single `telegram_configs` entry using
  `bot_token_file`. No inline token.
- **Zero child routes.** Every alert — all 56 rules, both severities — reaches
  the same receiver. The `critical`/`warning` distinction has no delivery
  consequence today.
- One inhibition, `critical` suppressing `warning`, `equal: [alertname,
  instance]`. It uses the **deprecated `source_match`/`target_match`
  spelling**, not `source_matchers`/`target_matchers`.
- `templates`: none.
- `global`: `resolve_timeout` only. No SMTP, consistent with telegram-only
  delivery.
- **No `--web.enable-lifecycle`.** Alertmanager cannot be reloaded over HTTP;
  a configuration change needs SIGHUP or a container recreate. Prometheus and
  Alertmanager therefore have *different* activation mechanisms, which any
  promotion lane has to handle rather than assume.

## 7. Backups, rollback and drift

`/opt/observability` contains **26 ad-hoc backup files** beside the live
configuration — 20 for `alerts.yml`, 8 for `prometheus.yml`, 2 for
`alertmanager.yml`, 4 for `docker-compose.yml` — in at least four naming
conventions: Unix epoch (`.bak.1784900394`), compact timestamp
(`.bak.20260816142004`), ISO-ish (`.bak-20260801T050357Z`), and semantic
(`.bak-crmerprunbook-20260730`, `.bak-hostrename`, `.bak-pregroupsplit`).

Material for a rollback exists. A rollback *mechanism* does not: there is no
ordering, no manifest, no record of which file corresponds to the currently
running configuration, and at least one file whose embedded date disagrees
with its mtime. Restoring would be a judgement call under pressure.

None of the backup names ends in `.yml`, which is the only reason a future
`rule_files` glob over that directory would not load them as rules. That is
luck, not design, and it is why this repository's releases keep rendered rules
in their own directory.

Host capacity: 8 CPUs, 23 GiB RAM (16 GiB available), root filesystem
**83% full** (320 G of 387 G used, 67 G free). Prometheus data 59.4 GB, Loki
data 34.9 GB — 94 GB of the usage, against a 30-day retention.

## 8. Secrets

Ten secret files under `/opt/observability/secrets`, all mode 600 except one
at 400, owned by the container users that read them. Contents were not read;
only sizes and digests were taken, and neither is recorded here. The exact
filenames are credential-file bindings and therefore private material under
ADR-0004.

There is one operator script, `ops/render-grafana-secret.sh`, mode 700.

## 9. Findings

Numbered so a later change can cite one. Severity is this census's judgement.

| # | Severity | Finding |
| --- | --- | --- |
| OBS-01 | high | No version control on `/opt/observability`. Every change is an unattributable in-place edit. This is the finding the whole repository exists to close. |
| OBS-02 | high | All seven images float on `:latest`. A restart can silently change the running version; nothing records what was deployed. |
| OBS-03 | high | Rules live in one 33 KB file loaded by an exact path. There is no per-product bundle, so no product can own its own rules and no bundle can be swapped atomically. |
| OBS-04 | high | Alertmanager has no child routes. `critical` and `warning` are recorded but not routed differently, so severity is presentational. |
| OBS-05 | medium | 53 of 56 rules have no runbook. |
| OBS-06 | medium | A retired product (CRM) still has a scrape job and four alert rules, and its dead target is firing `ServiceDown` — live noise from a decommissioned system. **Closed 2026-08-29 by a host edit — see §12.** |
| OBS-07 | **critical** | **Corrected — see §9.1.** The original wording of this finding was wrong. IPv4 containment is in place and persisted; the unremediated exposure is IPv6, by a mechanism that makes the existing IPv6 rules inert. Detail withheld here because it is unremediated. |
| OBS-08 | medium | No rollback mechanism (§7), only 26 unordered backup files. |
| OBS-09 | medium | `external_labels` is empty, so this evaluator's own series carry no environment or control-plane identity. |
| OBS-10 | **medium** | **The single inhibition is structurally inert**, not merely deprecated. It requires `alertname` to be equal across a `critical` source and a `warning` target, and no alert name is duplicated in the rule set — so it can never match anything. The `High`/`Critical` pairs it looks designed for are exactly the case an `alertname` equality cannot express. It also uses the deprecated `source_match` spelling. |
| OBS-11 | low | Root filesystem is 83% full; Prometheus and Loki hold 94 GB. |
| OBS-12 | low | promtail and cadvisor run as root with host mounts. |
| OBS-13 | info | CI pins older promtool/amtool than production runs (§2). |
| OBS-14 | info | The as-built uses `authorization.credentials_file`; the renderer emits `bearer_token_file`. Parity needs the former. |
| OBS-15 | high | **33 of 56 live rules have no attributable owner.** Only 23 trace to a repository. Six intact groups are unattributed, one of which has no candidate home at all. Detail and method in `observer-rule-provenance.md`. |
| OBS-16 | high | **Two live rules can never fire.** They select a label value that was renamed in the producing product before the rules were written, so they have matched nothing since the day they were added. |
| OBS-17 | high | **A rule repaired upstream 18 days ago is still running here in its unfixed form.** The product fixed it, merged it, and wrote up the lesson; the host never received it. This is precisely the drift class this repository exists to make impossible, observed before the control plane exists. |
| OBS-18 | medium | **Nine rules reference metrics no repository emits.** Their probe job is healthy, so the exporter runs — its source is simply not in any checkout. A supply-chain gap rather than a coverage gap. |
| OBS-19 | medium | **ERP has no rendered Foundation alert bundle in its repository.** It exists only on unmerged branches elsewhere, and adopting it as-is would *subtract* coverage: all three working ERP application rules map onto Foundation alerts that are in the omitted set, trading them for infrastructure alerts that duplicate `host_alerts`. PR 9's premise needs revisiting before it is scheduled. |

OBS-07 is the only finding that is not this repository's own business to fix,
and it should not wait for the promotion train.

## 9.1 OBS-07, corrected

This census first recorded OBS-07 as "several services published on all
interfaces with no host firewall restriction". **That was wrong, and the error
was mine.** The check behind it grepped the `DOCKER-USER` chain for
`--ctorigdstport`, which is the matching strategy used by two of the rule
blocks; it is not the only one. Counting only those matches returned zero for
the observability ports and the conclusion followed from the undercount.

A full read of the chain finds **198 IPv4 rules in `DOCKER-USER`** — nine
blocks covering the observability ports and others — dating from a fleet
firewall sweep on 2026-08-14, byte-identical to the persisted
`/etc/iptables/rules.v4`, with packet counters showing roughly fifteen days of
work. `iptables-persistent` is installed and enabled, so the IPv4 restriction
survives a reboot. **IPv4 containment exists, works and persists.**

The correct finding is narrower and worse:

**The exposure is IPv6, and the IPv6 rules that were supposed to cover it
cannot ever fire.** They are installed in the `ip6tables` `DOCKER-USER` chain,
which is only jumped from `FORWARD`. With no IPv6 DNAT in play, `docker-proxy`
terminates an IPv6 connection as an ordinary local process, so the traffic
arrives on `INPUT` and never traverses `FORWARD`. Every IPv6 rule in that
chain shows a zero packet counter, which is the observable signature of a rule
that is not merely unused but unreachable.

This was verified rather than inferred: probes from two other fleet hosts
found the affected ports open over IPv6, with a port known to be closed used
as a discriminating control. A third probe, from a host with no global IPv6,
failed even against the control port and was discarded — without the control
it would have read as a false pass, which is worth recording as the method
that made the result trustworthy.

Consequences that follow from the mechanism rather than from this host:

- A fix must **not** be written into `ip6tables DOCKER-USER`. It belongs on
  `INPUT`, or the IPv6 publish should be removed by naming an interface in the
  Compose port binding. An `INPUT` rule carries SSH, so it needs proven
  out-of-band recovery first (see below).
- **The same inert idiom was applied fleet-wide in the 2026-08-14 sweep.**
  Every host that sweep touched needs re-checking. That is outside this
  repository and is tracked in Knowledge, not here.

Two further facts from the same preflight, recorded because a later change
must not break them:

- **Loki cannot be loopback-bound.** It has six live remote log shippers.
  Every other affected service is reachable only from this host's own
  Prometheus, over the container bridge and by container name, so unpublishing
  those breaks nothing.
- **Source allowlists must be derived from observed addresses, not from DNS.**
  One shipper's hostname resolves to an address that was never seen
  connecting; it actually arrives from a different address in the same
  autonomous system. Narrowing to DNS-derived host addresses would have cut it
  off.

Out-of-band recovery is **present but unproven**: the provider console and a
serial getty exist, but no working root password was confirmed. That is a
blocker for any change touching the `INPUT` chain, and therefore for the IPv6
fix itself.

The port-level detail, the observed shipper addresses and the draft rules stay
in the private preflight material. This section says what class of thing is
wrong and what the fix must respect; it deliberately does not publish a map of
what is currently reachable.

### Why this correction is in the census rather than replacing it

A census that silently rewrites a finding is not evidence. The original
wording is left visible in the table above with a pointer here, so a reader
can see both what was claimed and why it was withdrawn. The undercount is also
a reusable lesson: a firewall chain has more than one matching strategy, and a
grep for one of them is not a count of the chain.

## 9.2 Provenance

A companion document, `observer-rule-provenance.md`, attributes every live
rule and scrape job to an owning repository and revision where one can be
found, and says plainly where one cannot. Its two load-bearing numbers are
**33 unattributed rules** and **9 rules whose producer metric no repository
emits**.

Both are inputs to the migration, not opinions about it: the delivery plan
blocks production promotion until the unattributed count reaches zero, so 33
is the size of the work rather than a note. The attribution method carries its
own sensitivity proof, and two tempting matches were refused as circular
because the document they appear in is this census.

## 10. The private inventory this census produced

Everything redacted above was captured into a private inventory, which is now
**preserved in the approved private store**. Per ADR-0004 public Git records
its identity and nothing else — never its location, which lives only in a
protected secret:

| Field | Value |
| --- | --- |
| Document | `observability-private-inventory.v1` |
| Status | preserved in the approved private store, read back and verified byte-exact |
| Environment | production |
| Version | 1 |
| sha256 | `1ecd635ba332c1c22883d6add04dceb52329ab36cfd4194da3edae33f9f5b7c5` |
| Contents | 16 logical targets (7 authenticated), 1 Alertmanager endpoint, 1 receiver binding |

The digest is over the document under a fixed canonical form — UTF-8, sorted
keys, two-space indent, **no trailing newline** — so a later census that
produces the same bytes proves nothing drifted, and one that does not
identifies drift without either version being published. A reader that adds a
trailing newline before hashing will report false drift on a correct
inventory. Promotion receipts record this pair, never its values.

## 11. What this changes about the plan

PR 3 cannot render this control plane byte-for-byte until the contracts gain:
digest-pinned images by measurement rather than by requirement (§2), the
`authorization` credential block (§4), an `external_labels` value that is
currently empty (§4), and a decision about whether the rendered layout adopts
a rules **directory** — which the as-built does not have — as part of the
cutover rather than as a same-shape reproduction (§4, OBS-03).

That last one is the substantive design question this census raises: a
byte-identical reproduction of the as-built would reproduce OBS-03. Parity and
correctness point in different directions here, and the resolution belongs in
PR 3's ADR, not in this file.

## 12. Post-census host change — the CRM decommission, 2026-08-29

Everything above is the host as it stood when the census ran. Later the same
day the Observer host was **changed by hand**, in the edit path this repository
exists to remove. Under the target contract that is drift; recorded here it is
**adoption evidence**, which is a different and more useful thing: it is the
exact delta the first rendered bundle has to reproduce.

The two are not in tension. A census is a dated statement about a moment, so
the sections above are left exactly as measured rather than quietly updated —
the same discipline §9.1 applies to a withdrawn finding. This section states
what the host became.

### Provenance of this section — read it differently from the rest

| Section | How it was obtained |
| --- | --- |
| §§1–11 | Read-only inspection over SSH, authorized by Michael, by the author of that census |
| §12 (this one) | **Reported by the operator who made the change**, and transcribed here |

Nothing in §12 was independently measured by this repository. That distinction
matters at exactly one point — the parity gate in "What this obliges" below,
which is where a transcription error would show up as a byte difference rather
than as a silent wrong assumption. Until that gate runs, treat every count
below as reported, not verified.

### What changed

The change executed the prepared deletion list in
`observer-rule-provenance.md` § "Every remaining CRM reference in the live
observability configuration" — all eleven items, A1–A5, B1–B5 and C1, across
the three files that list names. It also touched a fourth surface the census
never covered (Grafana dashboards; see OBS-20 below).

| # | File | Change | Removed |
| --- | --- | --- | --- |
| 1 | `prometheus/prometheus.yml` | scrape job `dotmac-crm-app` deleted (items A1–A5), instance label `dotmac-crm` | 435 bytes |
| 2 | `prometheus/alerts.yml` | rule group `dotmac_omni` deleted whole (items B1–B5): `CrmHighErrorRate`, `CrmDbPoolNearExhaustion`, `CrmLongRunningTransaction`, `CrmSlowRequests` | 2,464 bytes |
| 3 | secrets directory | one dead scrape credential shredded (item C1) — *basename withheld, ADR-0004* | 1 file |
| 4 | Grafana | dashboard `crm.json` deleted (title "Dotmac CRM", uid `dotmac-crm`, 8 panels) and its stray `crm.json.bak-rename2`; the `DotMac Omni` entry removed from `application-logs.json`'s `application` template variable, taking it from 6 query entries and options to 5 | 2 files, 1 variable entry |

Activation: Prometheus reloaded by SIGHUP; Grafana restarted, `/api/health`
returned 200. Preserved copies of everything removed are on the host under
`/root/crm-observability-removal-20260829/`, and the two Prometheus files carry
`.bak-crm-removal-20260829` backups beside them.

### The post-edit state, against the census

| Measure | §§4–5, as censused | After the change |
| --- | --- | --- |
| Scrape jobs | 16 | 15 |
| Active targets | 19 (18 up, 1 down) | 18 (18 up, **0 down**) |
| Rule groups | 9 | 8 |
| Alerting rules | 56 | 52 |
| Severity split | 33 warning / 23 critical | 30 warning / 22 critical |
| Rules with a `runbook_url` | 3 | 2 |
| Rules `UNATTRIBUTED` | 33 | **29** |
| Rules with a `PRODUCER-NOT-FOUND` metric | 9 | 9 (unchanged — all nine are `dotmac_identity_plane`) |
| Rules silent because their target is decommissioned | 4 | 0 |

Consequential note D1 of the deletion list is confirmed: the firing
`ServiceDown{job="dotmac-crm-app"}` cleared when the job went, without touching
`host_alerts`. The host now reports no down target at all.

### Which findings this closes, and which it does not

**OBS-06 is closed.** A retired product no longer has a scrape job, four alert
rules or a dead target generating live pages. This is the first of the census's
findings to be resolved, and it is resolved on the host rather than in this
repository — which is the shape of every remaining one until promotion exists.

**Nothing else is closed.** In particular OBS-01 is not merely still open, it
is *demonstrated again*: this change is a correct, careful, well-recorded set
of edits that no gate could have refused, no receipt records, and no drift
detector will notice. That is the finding, not a criticism of the change.

### Step 7's "prove the owner first" test, applied

The migration plan removes a dead rule, an inert inhibition or a retired
target only after its owner is proven. CRM passes: the product is fully
decommissioned — containers, volumes, images, vhost, certificate, units and
deployment directory destroyed on its named host on 2026-08-29, with only
off-host database backups retained. The retirement is no longer the
*incomplete* one the provenance ledger measured; the observability
configuration was the last live reference.

**`acme` does not pass, and its reference stays.** `application-logs.json`
still carries a `DotMac ACME : acme` entry. The `acme` platform runtime was
retired the same day on the ERP host, but retirement of a runtime is not the
same evidence as CRM's: its public name still resolves, its certificate is
still live to serve a tombstone, and the rollback archive is deliberately
intact. Removing the log-source entry would be an inference from a Knowledge
note rather than a proof, and step 7 asks for the proof. It is listed as
outstanding, not as done.

### What this obliges of the first rendered bundle

The first bundle this repository promotes must render to **this** state, not to
the state in §§4–5. Concretely, the parity target is 15 jobs, 8 groups and 52
rules, with no `dotmac-crm-app`, no `dotmac_omni` and no reference to the
shredded credential. A render that reproduces the census exactly would
reintroduce a decommissioned product's configuration, so §11's "byte-for-byte
reproduction of the as-built" now means the as-built **as of this section**.

That is a general property worth naming rather than a CRM detail: a cutover
that adopts a host's current configuration is racing that host's operators, and
the race is only winnable if every hand edit between census and cutover is
captured the way this one was. Each further edit before promotion widens the
delta this bundle has to carry.

### Two new findings this change surfaced

| # | Severity | Finding |
| --- | --- | --- |
| OBS-20 | medium | **Grafana dashboards and the Loki/promtail configuration are outside both the census and the planned bundle.** The change had to edit dashboard JSON and a template variable that nothing owns, reviews or renders, so the stack has a second unversioned edit surface with the same properties OBS-01 describes. **Accepted 2026-08-29 as scope, not carried as a gap — see `docs/adr/0007-the-controller-owned-release-boundary.md`:** the first adopter brings ALL controller-owned deployment configuration under one release boundary, and the over-broad "every running byte" formulation is withdrawn in favour of *every controller-owned image and deployment-relevant configuration byte explained by an authorized digest*. |
| OBS-21 | low | **promtail stamps a retired host label on surviving logs.** Logs from the `son_erp` workload still arrive labelled with the decommissioned CRM host's name, because the shipper's label was never updated when the workload was rehomed. It is a promtail configuration fact, so it belongs to this repository's scope, and it is a worked example of OBS-20: no gate reads that file. ADR-0007 brings that file inside the release boundary, which turns this from a curiosity nobody owns into a defect repairable through the promotion path rather than by hand. |
| OBS-22 | info | **Observer's firewall chains are iptables, so the rendered interface match is `-i wg0`** — the nftables spelling would be wrong there. The `iif`-resolves-at-load boot hazard is **nftables-only and applies to the control runner, not Observer**; carrying that note across would send somebody hunting a boot problem that cannot occur on this host. Detail in §13. |
| OBS-23 | medium | **A correctly-functioning deny-by-default control was read as a broken host, three times on 2026-08-29.** The tunnel's first probe failed with the ACL innocent: the prober's own egress policy permitted ICMP but not TCP, so ping succeeded while TCP was dropped. A successful ping is not reachability evidence for TCP when egress policy is protocol-scoped. Detail and the general prior in §13. |

### An inconsistency noticed while amending, and deliberately not repaired

§7 states "26 ad-hoc backup files" and then breaks them down as 20 + 8 + 2 + 4,
which is 34. One of the two numbers is wrong and this amendment has no evidence
for which. It is flagged rather than corrected, because guessing at a measured
figure is how a census stops being evidence. The change above added two further
backup files, so whichever figure is right is now two low.

## 13. The control path to the secret store — 2026-08-30

Recorded because it changes what governs privileged access to Observer's
secret store, and because two findings from the apply are reusable well beyond
it.

Same provenance caveat as §12: **reported by the operator who made the change**,
not independently measured by this repository. Addresses, ports and the tunnel's
subnet are resolved material under ADR-0004 and appear nowhere below; this
repository's own private-material scanner was run against a draft of this
section carrying them and refused it, which is how the wording arrived at
logical terms.

### What changed

A WireGuard tunnel now carries the control runner's access to the secret store:
a point-to-point `/30`, Observer at one end and `dotmac-control-runner` at the
other. Handshake established, round-trip latency approximately 146 ms.

Verified in both directions, which is the part that matters:

| Path | Result |
| --- | --- |
| Runner → the store's **tunnel-side** listener | reachable |
| Runner → the store's **ordinary** address | **refused**, terminal DROP |

Persisted, reloaded, controls repeated, rollback cancelled.

The second row is the finding, not a footnote. The runner's access is bound to
the **tunnel identity** and its ordinary address was never added to the
plaintext listener's allowlist — so the containment holds on the path the
runner does not use, while the path it does use is authenticated by how the
channel was established rather than by what a packet claims about its source.

### The ACL rows gained an interface field

Rows are now `family|cidr|iface|enforced|label`, and every pre-existing row was
written out with an explicit `any` rather than left empty. **An omission with
an ambiguous meaning is not a default**, and the difference between "this rule
deliberately matches any interface" and "somebody forgot the field" is exactly
the kind of thing a later reader resolves in whichever direction suits them.

`required.assert` now asserts the `cidr|iface` **tuple**. A CIDR-only assertion
passes on a rule that has silently lost its `-i`, which would leave the
assertion green while the property it exists to protect was gone — the same
shape as the census's own inert IPv6 rules, and as the `SUPERSEDE-NO-CHANGE`
check that compared the wrong digests.

Under Observer's `rp_filter = 2`, that interface match is what makes tunnel
identity **real rather than forgeable**. Without it the rule is a source claim,
and a source claim is something a packet asserts about itself.

### OBS-22 — the rendered firewall form is iptables, and one hazard does not travel

Observer's `OB8200-*` chains are **iptables**, so the rendered match is
`-i wg0`. The nftables spelling would have been wrong there.

Related and more important, because it is the kind of note that causes wasted
work: the **`iif`-resolves-at-load boot hazard is nftables-only, and applies to
the runner, not to Observer.** Do not carry that hazard note across to
Observer's rules. Doing so would send somebody hunting a boot problem that
cannot occur on that host — a hazard recorded against the wrong system is worse
than one not recorded at all, because it is acted on.

### OBS-23 — a working deny-by-default control read as a broken host, three times in one day

The first tunnel probe failed and **the ACL was innocent**. DNAT showed zero
packets. The runner's own deny-by-default *egress* firewall was dropping the
attempt: it permits ICMP but not TCP to unlisted addresses.

Which is precisely why **ping succeeded and TCP did not**, and that asymmetry
is the diagnostic signature worth remembering:

> A successful ping is not reachability evidence for TCP when egress policy is
> protocol-scoped. Before concluding a target is broken, check the **prober's
> own egress**.

This was the third time on 2026-08-29 that a correctly-functioning
deny-by-default control was first read as a broken host — alongside the store's
port being twice mis-called publicly reachable, and this repository's own
coordinator briefly reading a closed inbound SSH port as an unprovisioned VM.
The pattern is consistent enough to name: **in a fleet that has recently been
contained, the prior for "unreachable" shifts from "it is broken" to "a control
is working".**

The repair went into the egress refresh script rather than only the live rule
set, so it survives the refresh timer. A fix applied only to the running state
is undone by the thing that regenerates it — the same lesson `AGENTS.md` rule 2
states for `/opt/observability`.

## 14. Independent revalidation of §13 — 2026-08-30

§§12 and 13 carry the same provenance caveat: both were **reported by the
operator who made the change** and transcribed. This section is the first part
of that material to be **independently measured** by a second party, and it is
recorded separately rather than folded into §13 so the two provenances stay
distinguishable.

Method: read-only inspection over authorized SSH — `wg show`, `sysctl`,
`iptables`/`ip6tables` listings with counters, the persisted rulesets, the
`systemctl` state of the persistence unit, the Prometheus read API, and TCP
reachability probes from a second fleet host. **Nothing on either host was
changed.** No credential value was read and no resolved address, port or store
path appears below (ADR-0004); the reachability results are stated as a class
rather than as a map, for the reason §9.1 gives.

### What was confirmed

| Property | Result |
| --- | --- |
| Tunnel liveness | Handshake current at inspection; the peer's `allowed-ips` is the runner's single-address prefix, so cryptokey routing already constrains it |
| Reverse-path filtering | Loose mode on both the global and the tunnel scope, which is what makes an interface match meaningful rather than decorative |
| The tunnel-bound accept row | Present, carrying **both** the runner's single-address prefix **and** the interface match, with a non-zero counter — live, not aspirational |
| Rendered firewall form | **iptables**, so the match is `-i wg0`. OBS-22 stands: the nftables `iifname` spelling would be wrong on this host, and the `iif`-resolves-at-load boot hazard remains a runner-only concern |
| Terminal deny | Live on both families; counters incremented under probe |
| Persistence | Both rulesets carry the rows, and the persistence unit is enabled and active |
| The store's scrape job | Healthy, with a recent successful scrape |
| Post-CRM parity | 15 jobs, 18 active targets, **none down**, and **no CRM job present** |

That last row independently confirms §12's reported parity numbers for the
first time. §12 remains operator-reported for everything else it states.

### Both address families, each with a positive control

The store's published surface was probed from a fleet host that is **not** in
its allowlist, testing each family on its own path in a single pass:

- **Both families refuse** the store's surface.
- **Multiple control ports on the same host, in the same pass, over the same
  family, were reachable** — so the refusal is a property of that surface and
  not of the prober's egress, its routing, or a missing address family.

The control half is not ceremony. §9.1 records a probe discarded precisely
because it failed against its control, and OBS-23 records three occasions in
one day where a working deny-by-default control was read as a broken host. A
refusal observed without a control in the same pass proves the probe ran, not
that access is shut. An earlier single-control pass during this revalidation
did read as a false negative on one family and was discarded on exactly those
grounds before the broader control set was used.

### The IPv6 rule is on the chain the traffic actually traverses

OBS-07's finding was that IPv6 rules sat in a forward-only chain that
`docker-proxy`-terminated traffic never reaches, so they could not fire. **For
the secret store's surface that is no longer the case:** the deny is installed
on the chain local traffic actually arrives on, and its counter **incremented
under the external probe**. That increment is the sensitivity proof — a
zero-counter rule is indistinguishable from an unreachable one, which is the
whole substance of OBS-07, so "the rule exists" was not accepted as evidence
here.

This says nothing about the other ports OBS-07 covers. That finding stays open.

### Persistence is not authorship — and two inert chains

The persistence mechanism snapshots live state wholesale. So the rows being
present in the persisted rulesets proves they **survive a reboot**, and proves
nothing whatever about **who created them or when**. iptables carries no
per-rule provenance, counters measure use rather than origin, and the persisted
files' timestamps date the snapshot, not any individual row. Any claim about
authorship has to come from the change record, not from the firewall.

Two **empty chains with no jump** remain on the host, one per family, left by
the known `swap_jump` defect in the apply script — its delete loop exits
without failing the function, so a stale artefact can survive while the run
reports success. They are inert: nothing jumps to them, and the terminal deny
sits behind them regardless. They are recorded because they **read as live** to
anyone listing the chains, which is the cost of that defect even while it is
harmless.

### What this section does NOT establish

- It does not establish who authored any firewall row (above).
- It does not re-measure §12's rule, group or attribution counts; only the job,
  target and CRM-absence figures were checked.
- It does not clear OBS-07 beyond the single surface named here.
- It does not verify the private inventory's contents. Populating the public
  `inventory/` requires the private document's logical `target_id` vocabulary,
  which was not retrievable under this session's access; the store's KV version
  and storage shape were confirmed, its contents were not read, and no target
  vocabulary is asserted anywhere in this repository as a result.

## 15. The stored private inventory does not satisfy its own contract — 2026-08-30

§10 records that the census's private inventory was preserved in the approved
store as version 1 with digest `1ecd635b…`. Both facts are **confirmed**: the
document was read back on 2026-08-30, its canonical form is **7,326 bytes**,
and it hashes to exactly the digest §10 records. That digest is now
independently recomputed rather than cited.

What §10 did not say, because the contract did not exist when it was written,
is that **the stored document is not an `observability-private-inventory.v1`
document.** It declares
`schema_version = "observability-private-inventory.v1 (PROPOSED)"` — the
capture format the census produced in PR #2, three PRs before ADR-0006 accepted
the contract in PR #9. Validated against
`contracts/private-inventory.schema.json` it produces **68 errors**.

Shape only below; no value from the document appears here.

| | Contract (`.v1`) | Stored document (`.v1 (PROPOSED)`) |
| --- | --- | --- |
| Top level | `schema_version`, `document`, `version`, `environment`, `host`, `targets`, `federations`, `receivers` | `schema_version`, `version`, `environment`, `targets`, `receiver_bindings`, `alertmanager_endpoints`, `captured_at`, `captured_from`, `note` |
| Missing | — | `document`, `host`, `federations`, `receivers` |
| Extra (refused by `additionalProperties: false`) | — | `alertmanager_endpoints`, `captured_at`, `captured_from`, `note` |
| A target entry | `target_id`, `endpoints`, `credential` | `target_id`, `resolved_endpoints`, `credential`, `metrics_path`, `params`, `scheme`, `static_labels`, `tls_config` |
| A receiver entry | `credential_ref`, `credential`, `destination` | `receiver`, `credential_file`, `kind`, `destination` |
| Federations | own array | folded into `targets`, so `targets` holds **16** entries including the federation |

### Why this blocks the CRM supersession outright

`inventory-digest` and `inventory-apply` both begin by loading the previous
document through `load_private_inventory`, which validates it. The stored
document does not validate, so **the supersession workflow fails at its first
tool step** — before compare-and-set, before any write. The workflow's own
precondition check tests only that `inventory/control-plane.toml` exists, so it
passes that guard and then fails later, which is a worse failure shape than
refusing up front.

The repair is not a retirement. Bringing the document to the contract means
adding `document` and a `host` binding — and `host` requires `identity` and
`ssh_alias`, which are **resolved values**. That is provisioning, and
`supersession-request.v1` deliberately has no field for it: "retiring needs a
logical name while provisioning needs a resolved value that must not enter
public Git or a CI input." So the migration is a **human operation against the
private store**, and it must happen before any CRM retirement.

**A supersession request must not be written against `1ecd635b…` today.** The
migration rewrites the document, which changes its digest, and the digest is
the compare-and-set precondition. A request naming the pre-migration digest
would be refused after migration — correctly, but only after looking as though
the work had been done.

### Two contract gaps the comparison exposes, both material

Populating `inventory/` surfaced two things the public contract cannot express,
and the stored capture carries both — so these are omissions in the accepted
contract rather than in the capture.

- **`params`.** The live OpenBao job sends `format=prometheus`, without which
  OpenBao emits its own JSON rather than Prometheus exposition.
  `observability-target.v2` has no `params` field, so a render from the public
  contract alone scrapes the wrong format. The stored document has `params`.
- **`static_labels`.** The as-built assigns logical `instance` labels
  (`dotmac-observe`, `dotmac-db-primary`, `dotmac-s3`, `seabone`) rather than
  letting them default to the endpoint. Neither the public target contract nor
  the private `target_binding` has anywhere to put them, so byte-parity with
  the as-built is currently impossible for every job that carries one. The
  stored document has `static_labels`.

`tls_config` and `alertmanager_endpoints` are in the same position and need the
same decision: carried into the contract, or consciously dropped with the
consequence written down.

### Provenance

Independently measured on 2026-08-30 by a second party, read-only, by the
method §14 describes. Only the document's **shape** was read out — key names,
array lengths, error paths and keywords. No endpoint, credential binding,
destination, host identity or store field name was printed, and nothing was
written to disk. The digest and byte length above are the whole of what was
derived from its contents.

## 16. Four measured faults, the federation's origin, and the unattributed estate — 2026-08-30

Measured read-only on the named host, by §14's method. Every figure below is a
command's output rather than a recollection, and where a claim is an absence it
carries the positive control that proves the probe read something.

### 16.1 The mail facility has been dead for a month

`journalctl -u rsyslog --since -30d | grep -ci suspend` returns **10,161**.
The reason is in the same journal, twice: `file '/var/log/mail.log': open
error: Permission denied`, at 01:40 on 23 August and 01:02 on 30 August — the
two weekly logrotate runs, which HUP rsyslog and make it try the open again.

The mechanism, which is entirely ordinary and entirely undeclared:

| Fact | Measured |
| --- | --- |
| `/var/log` | `root:syslog`, mode `755` |
| rsyslog's identity after privilege drop | `$PrivDropToUser syslog`, `$PrivDropToGroup syslog` |
| `/var/log/mail.log` | absent — `ls: cannot access '/var/log/mail*'` |
| The action | `mail.* -/var/log/mail.log` in `50-default.conf` |
| Its number | `action-5-builtin:omfile`, the sixth omfile action in include order |
| The facility's writer | `postfix@-.service`, active |

A privilege-dropped writer cannot create a file in a directory with no group
write bit. It is not a permissions bug in rsyslog; it is that nobody had
written down who creates that file. Every mail-facility message for at least
thirty days was discarded.

`logrotate.d/rsyslog` lists `/var/log/mail.log` and inherits the global
`create` — with **no arguments**, which reuses the *original* file's owner and
mode and does nothing when the original does not exist. `missingok` then skips
the stanza silently.

**Fixed by ADR-0008, in the bundle rather than on the host.** The directory
stays `0755`; systemd-tmpfiles creates the file as root with the declared
owner, group and mode, and logrotate recreates it the same way with an explicit
`create 0640 syslog adm`, `su`, `delaycompress` and a `postrotate` reopen. CI's
`rotation-proof` job rotates an isolated real file, writes a controlled
`mail.info` message through a real rsyslogd, and runs three negative controls
that must each fail.

### 16.2 Alertmanager is gossiping with itself

`/api/v2/status` reports a `peers` array of **length one**, whose single entry's
`name` equals the cluster's own `name` — it is peered with itself. The peer's
address is its container address on the compose network and is redacted here;
the private-material scan refused the first draft of this line, correctly, and
the fact that matters is the length and the identity rather than the address. The log carries, every fifteen minutes for
weeks: `dropping messages because too many are queued  current=4097 limit=4096`.

Alertmanager clusters by default and binds its gossip port whether or not a
peer exists. Nothing had declared this deployment a singleton, and an omission
is not a declaration. The bundle renders `--cluster.listen-address=`, which
disables clustering outright; routing, receivers, inhibition and templates are
byte-identical afterwards, asserted by comparison rather than claimed.

### 16.3 Eighteen of eighteen targets green, 1,858,942 samples rejected

`/api/v1/targets?state=active` returns **18 active targets, all `up`**.
`prometheus_target_scrapes_sample_duplicate_timestamp_total` at the same
instant: **1,858,942**.

Target health and ingestion integrity are separate facts and every check the
fleet had read only the first. ADR-0008's verification gate emits
`(health) unless (integrity)`, which fires exactly in the state a scrape-health
check reports as green.

### 16.4 The federation collision originates in SUB, not in Observer

`scrape_pool=dotmac-sub-federation`, bursts of two to four consecutive 15-second
scrapes with a constant `num_dropped` (68, 69, 84, 102, 105, 196, 387 observed),
then nothing for minutes.

**Observer's side is clean, and the checks are non-vacuous.** 312 real
`/federate` payloads were captured (41 at 15 s, 271 at 5 s), each 8,900–13,900
sample lines:

- zero duplicate label sets within any payload, with labels normalised and
  sorted rather than compared as strings;
- zero post-relabel collisions after applying Observer's own
  `^(up|scrape_.+)$ → federated_$1` rename, which is injective on names;
- zero series already named `federated_*` upstream, so the rename cannot
  collide with an existing name;
- `honor_labels: true` target-label injection simulated for the 5,252–5,428
  samples per payload that carry no `job`/`instance`: still zero collisions.

**Sub's side is where the duplication is, with the exact series.** Two bursts
were captured in flight (16:01:43–16:01:58 Z and 16:11:28–16:11:58 Z). Across
snapshots inside those windows, **171 (series, timestamp) pairs returned more
than one value**, all from four metric families and all under one identity:

| Metric family | Pairs |
| --- | --- |
| `http_requests_created` | 64 |
| `http_request_duration_seconds_created` | 58 |
| `http_request_duration_seconds_sum` | 48 |
| `redis_operations_created` | 1 |

All carry `job="dotmac-app", instance="dotmac-app"`. A representative case, at
a fixed federate timestamp `1788105665856`:

```
http_request_duration_seconds_created{job="dotmac-app",instance="dotmac-app",
  method="GET",path="/admin/customers/person/…/billing/ledger",status="200"}
    1788104955.665218   returned at 16:01:07 and 16:01:12
    1788104955.6652184  returned at 16:01:18, 16:01:23, 16:01:28, 16:01:34, 16:01:39
```

Same series, same timestamp, two values differing in the last significant
digit — a float64 round-trip difference, which is the signature of **two
samples stored for one identity** rather than of a value that changed.

The mechanism is confirmed from Sub's own store. `-dedup.minScrapeInterval` is
**set to `1ms`** on that VictoriaMetrics, and its counters read
`vm_deduplicated_samples_total{type="merge"} 1546135` and
`{type="select"} 67827`. Deduplication only counts when more than one sample
exists for one series in one interval; select-time and merge-time dedup resolve
independently, so the value returned for a given (series, timestamp) can change
between two `/federate` calls until the affected block is merged. That is
exactly the bursty, self-clearing behaviour Prometheus reports.

The colliding timestamps are 600,000 ms apart and the bursts are ten minutes
apart, which matches a ten-minute write cadence for these series.

**Disposition: hand to the Sub lane.** Observer imports the fault and must not
mask it. `honor_timestamps: false`, a broad drop and arbitrary deduplication
were each considered and rejected in ADR-0008: all three make the symptom
invisible rather than absent, and the samples would still be wrong upstream
with nothing ever saying so again. Observer's change is the ingestion-integrity
gate, which makes the rejection visible.

### 16.5 The IPv6 rules are in a chain IPv6 does not traverse

`ip6tables -S DOCKER-USER` carries DROP rules for **8200, 9090, 9093, 3100,
8080, 8000 and 9100**. `ip6tables -S INPUT` carries one rule, for 8200.

An IPv4 container publish is forwarded and traverses `DOCKER-USER`; an IPv6 one
terminates on `INPUT`. Every port those seven rules name reads as closed and is
open on IPv6 — and `docker ps` confirms all seven publish on `[::]`.

sshd is `0.0.0.0:22` and `[::]:22` with `permitrootlogin without-password` and
an iptables INPUT policy of ACCEPT.

**Declared, not applied.** `inventory/bundle.toml` declares the intended
posture and the renderer derives the chain from the surface kind and the
address family, so the rule cannot be written into the wrong one. Applying it
is a Foundation promotion with a positive control in the same pass — a firewall
change to port 22 that is wrong is a change nobody can get back in to undo, and
applying it by hand would also be using a manual command as evidence that the
controller works.

### 16.6 `systemd-networkd-wait-online` — diagnosed before anything was cleared

Not cleared. `systemctl reset-failed` would destroy the evidence and change
nothing, because the cause is still present and the unit will fail again at the
next boot.

| Fact | Measured |
| --- | --- |
| Failed since | 2026-05-10 17:01:47 CEST, under the pre-rename hostname `vmi3291425` |
| Uptime | 112 days — it has not re-run since that boot |
| Failure | `Timeout occurred while waiting for network connectivity`, after 37.6 s |
| The wait | netplan drop-in: `systemd-networkd-wait-online -i eth0:degraded` |
| eth0 | `State: routable (configuring)`, `Online state: online` |

The link is online and routable; networkd's SETUP state never advances past
`configuring`, and `-i eth0:degraded` waits for `configured`. Nothing depends on
the unit succeeding: every consumer of `network-online.target` — docker, nginx,
postfix, `wg-quick@wg0`, cloud-init — started anyway, and has been up 112 days.

`cloud-init.service` is failed from the same boot for the same reason.

**Disposition: a stale boot-time artefact with a live cause.** Clearing it
without changing either the drop-in or the netplan configuration would hide a
condition that recurs on every boot.

### 16.7 cAdvisor CPU, over a representative window

A single 52% sample had been treated as a sustained fact. Over real windows it
is not:

| Window | `rate(container_cpu_usage_seconds_total{name="cadvisor"}[5m])` |
| --- | --- |
| 24 h mean | **12.71%** of one core |
| 24 h p95 | 14.11% |
| 24 h max | 16.42% |
| 7 d mean | 13.45% |

The host has 8 cores, so the 7-day mean is about **1.7% of the machine**. No
action; the earlier figure was one scrape.

### 16.8 The unattributed estate, and a signed deletion manifest

**Nothing was deleted, and `docker prune` was not run.** Prune decides for you
and records nothing about what it decided, which is the opposite of a manifest.

Measured: **86 containers**, 16 networks, and a volume list far longer than the
rostered set. `inventory/bundle.toml`'s roster owns 5 services, 1 network and 5
volumes. Everything below is present on the host and owned by nobody in that
roster.

Disk is at **85%** (326 G used of 387 G, 61 G free), so this is worth doing —
but as a decision, with an owner attributed to each row, not as a sweep.

| Group | Count | Evidence of purpose | Attributed owner | Proposed disposition |
| --- | --- | --- | --- | --- |
| `sla-pr2-*` (exited/created) | 39 | Named for `dotmac_sub` PR 2's SLA validation; image `dotmac-sub-validation-deps:sla-pr2-hypothesis-6.165.0`; all exited ≥ 3 weeks | Sub lane | DELETE after target-level approval |
| `*-full`, `subtest` (exited) | 8 | Image `dotmac-sub-validation-deps:rebased-ueu52p`; all exited ≥ 3 weeks | Sub lane | DELETE after target-level approval |
| `dotmac-positive-admission-pg-*` | 2 | Running Postgres for an admission experiment; 3 weeks old | Sub lane | CONFIRM then delete — running, may hold state |
| `dotmac_sub_party_collision_pg`, `subscriber-retirement-pg-20260819`, `sla-pr2-postgres` | 3 | Running experiment databases | Sub lane | CONFIRM then delete — running, may hold state |
| `pq1-*`, `pq2-*`, `netrecon-5459-*`, `dotmac_billing_test_20260817-*`, `vendor_billing_adoption_test-*` | 5 | Named test compose projects, running | Unattributed — needs an owner named | HOLD pending attribution |
| `cloudpg`, `subpg`, `sp-pg`, `erp-pg` | 4 | Running, published on host ports | Unattributed — needs an owner named | HOLD pending attribution |
| `glitchtip`, `glitchtip-worker` | 2 | Running error tracker, published `0.0.0.0:8000` | Unattributed — needs an owner named | HOLD; roster it or retire it |
| `claude_knowledge-*` | 4 | The Knowledge MCP server; a rostered scrape target already | Knowledge lane | ROSTER, do not delete |
| `node-exporter`, `cadvisor`, `openbao` | 3 | Rostered scrape targets, not bundle services | Platform operations | ROSTER as external services |
| Networks `sla-pr2-validation`, `dotmac-positive-admission-*`, `lifecycle-authority-net-20260804`, `netrecon-5459_default`, `pq1_default`, `pq2_default`, `dotmac_billing_test_*`, `vendor_billing_adoption_test_*` | 8 | Created by the container groups above | As their containers | DELETE with their containers |
| `docker-compose.yml.bak.*` (3) and `prometheus/alerts.yml.bak*` / `prometheus.yml.bak*` (19) under `/opt/observability` | 22 | Hand-edit residue — AGENTS.md rule 2 | Observability control plane | DELETE at the first promotion, which replaces the tree with an immutable release |

**This manifest is not an authorization.** Under AGENTS.md rule 17 a live change
needs a human to name the target, and under ADR-0008 an unrostered resource is a
finding rather than a candidate. Two rows need an owner named before they can be
dispositioned at all, and every DELETE row needs explicit target-level approval.
Deletion, when approved, is snapshot → apply → re-observe → rollback evidence
like any other live change.

### 16.9 CRM residue: no live binding survives; retained data does

Swept 2026-08-30 with a positive control on every probe, because "no
references" over a tree the sweep failed to read is indistinguishable from "no
references" over a clean one.

| Surface | Positive control | CRM references |
| --- | --- | --- |
| `prometheus.yml` | 4,243 bytes, 13 known-token hits | **0** |
| `alerts.yml` | 31,166 bytes, 8 hits, 0 recording rules, 40+ alerts enumerated | **0** |
| `alertmanager.yml` | 1,008 bytes, 1 hit | **0** |
| `loki-config.yml`, `promtail-config.yml` | 771 / 731 bytes | **0** |
| `docker-compose.yml` | 4,863 bytes, 29 hits | **0** |
| Grafana `grafana.db` | 86 tables read, 4 datasources returned | **0**, and **zero dashboards of any kind** |
| Alertmanager runtime | 1 receiver (`default`), 0 silences | **0** |
| Blackbox / probe jobs | `identity-probe` is a bespoke exporter; no blackbox exporter exists | n/a |
| Active targets | 18, enumerated | none CRM |
| Prometheus metric names | 2,573 read | 0 CRM-named |

**The Grafana UNKNOWN is resolved, not inherited.** The database was read
directly as a read-only SQLite copy — no credentials were needed and none were
used, so there was no secret material to destroy. It holds four datasources
(Prometheus, Loki, Alertmanager, DotMac-Sub-VictoriaMetrics) and **no dashboards
at all**.

**What does survive is retained DATA, which is history rather than a
dependency.** Prometheus still holds `job="dotmac-crm-app"` and
`instance="dotmac-crm"` label values; Loki still holds `app="dotmac_crm"`,
`project="dotmac_crm"` and `host="crm"`. All recorded before the 2026-08-29
retirement, all ageing out with their stores' retention, and nothing scrapes,
ships, routes or alerts on any of it.

**Disposition: CLEAR.** No monitoring binding to CRM survives in Observer, and
ADR-0008 makes it a standing property rather than a finding with a date on it:
`retired` declares the three spellings and the render refuses a tree that
mentions any of them.

### 16.10 One thing this section does not settle

Grafana's `DotMac-Sub-VictoriaMetrics` datasource points at a **different
address** from the one Prometheus's `dotmac-sub-victoriametrics` job and its
federation scrape use. Two addresses for one logical upstream, with nothing
comparing them. Not investigated here; recorded so it is not discovered again
from scratch.

### 16.11 Grafana datasource repair and Loki query-path boundary — 2026-09-04

The VictoriaMetrics mismatch above is repaired on the live Observer host. The
provisioned `DotMac-Sub-VictoriaMetrics` datasource now resolves to the same
private-inventory target as the `dotmac-sub-victoriametrics` scrape instead of
the unrelated Academy host. After a Grafana-only restart, Grafana's datasource
health endpoint successfully queried the Prometheus-compatible API. The
pre-change datasource file and a consistent Grafana SQLite backup are retained
in the host's restricted operations backup directory.

The reported Loki failure was a diagnostic API-boundary mismatch, not a
production caller. Loki health and label queries succeeded, and stored Grafana
queries use lowercase `backward`. Requests authenticated as
`sa-1-logs-read` came only from a non-Fleet source inside the documented
workstation/NOC range during the compatibility probes. They
mixed legacy or duplicated datasource-proxy paths with Grafana 13's
`/api/ds/query` plugin path and sent uppercase `BACKWARD`; the plugin rejected
that value before contacting Loki. The native plugin request succeeds with
lowercase `backward`, and direct Loki accepts the uppercase wire value. No bad
request recurred after the probes. A global server-side rewrite would hide a
malformed caller and was not introduced.

The durable bundle now declares that datasource by its stable Grafana UID and
the existing logical `dotmac-sub-victoriametrics` target. Its URL is derived
from the target's public scheme and private single-endpoint binding; the
resolved address does not enter this public repository. The renderer also
materializes valid empty plugin and alerting provisioning documents, closing
the missing-directory errors observed after the Grafana restart.

### 16.12 Fleet coverage is declared but not deployed — 2026-09-04

The authoritative fleet registry lists **25 active hosts**, 24 marked
production. Observer currently has 18 healthy Prometheus targets, but those are
service/exporter targets rather than one host record per fleet member. Joining
the target instance labels and Loki `host` labels back to fleet identity shows
direct central evidence for only **7 active hosts**: `academy`, `db-primary`,
`erp`, `observe`, `s3`, `seabone`, and `sub-prod`. Only five of those appear in
Loki's current host-label set; `db-primary` and `s3` have metrics without a
central host log stream.

No direct host-level Prometheus or Loki evidence exists for 17 active
production hosts: `control-runner`, `idp-ha-1`, `idp-ha-2`, `idp-ha-3`,
`idp-live`, `integrator-vendor-control`, `mail-dotmac`, `mail-nhia`,
`nhia-moh-cloud`, `ns1`, `ns2`, `ns3`, `proxmox`, `son-erp`, `web-cache`,
`workspace`, and `zabbix`. The non-production `test-server` is also absent.
The healthy `identity-probe` is service-level evidence and does not prove host
metrics or logs for any identity node. Loki still lists `academy-labs` and
retired `crm`; retained labels are not active fleet coverage.

This is deployment debt, not a missing decision. ADR-0009 already requires one
Grafana Alloy agent per Linux VM, with a host-only or Docker profile and a
no-overlap cutover from legacy writers. The profiles and architecture tests
exist under `fleet/alloy/`; no per-host activation receipts exist. Start with
`test-server` as the non-production canary, then a low-risk production cohort.
DNS, mail, database and orchestration hosts remain later cohorts as ADR-0009
requires.

## 17. The verdict is `rendered_guarded`, not `deployed_repaired` — 2026-08-30

The four faults of §16 are closed **in the renderer**. Each is now
unrepresentable in any newly rendered bundle, which is a stronger and more
durable property than "fixed" — a fix can be undone by the next hand edit,
whereas a shape the contract cannot express stays unexpressible.

**Observer is not yet running a rendered bundle.** Nothing on the host has been
repaired, and reporting the first as though it were the second is the specific
error this vocabulary exists to prevent.

### The one measurement that settles it

| Measured 2026-08-30T18:48:17Z | Value |
| --- | --- |
| Active targets healthy | **18 / 18** |
| `prometheus_target_scrapes_sample_duplicate_timestamp_total` | **1,864,926** |

Every target green. Nearly 1.9 million samples rejected. That single pair is
the whole argument for the ingestion-integrity gate, and it makes the case
better than the rule statement does: a check that reads only the first column
reports a healthy system while data is being dropped.

### `1,864,926` is the PRE-PROMOTION BASELINE, recorded so the delta is checkable

Read at `1788115697` (2026-08-30T18:48:17Z), up from 1,858,942 measured earlier
the same day — it is still climbing, which is itself the point.

**Do not reset this counter.** Resetting it makes "no new rejected samples"
true by construction: the predicate would pass instantly on a broken system and
look identical to a genuine pass. The historical rejections must stay visible.
What condition 4 asserts is the **delta from this recorded baseline**, not that
the absolute value is zero.

That is now enforced rather than merely written down. `GATE-INTEGRITY-NOT-DELTA`
refuses an integrity predicate that compares a raw counter instead of wrapping
it in `increase`, `rate`, `irate`, `delta`, `idelta` or `resets` — because a
bare `counter == 0` is satisfiable by a reset, a fresh TSDB or a container
restart, and a predicate made true that way cannot be told from one made true
by a repair.

### The six conditions for `deployed_repaired`

None is met today.

| # | Condition | State |
| --- | --- | --- |
| 1 | Platform CP authorizes the exact bundle digest | **blocked** — the issuer does not exist yet |
| 2 | Foundation applies those exact bytes to Observer | blocked on 1 |
| 3 | Live read-back matches the authorized **14-file** tree — all fourteen compared, not sampled | blocked on 2 |
| 4 | All 18 targets healthy **AND** zero new rejections against the baseline above, counter not reset | blocked on 2 |
| 5 | Mail rotation, Alertmanager singleton and **both-family** firewall behaviour pass live probes | blocked on 2 |
| 6 | Rollback restores the prior digest and produces a receipt | blocked on 2 |

Condition 4 is a **conjunction**, and either half alone is the failure already
measured above.

Condition 5's *both-family* is load-bearing for the same reason §16.5 was: the
seven IPv6 rules in `DOCKER-USER` are dead and every port they name is open, so
a v4-only probe passes while v6 stays exposed. Each probe also needs a positive
control in the same pass — a refusal without one proves the probe ran, not that
access is shut.

Condition 6 is the one a lane skips when the forward path works. **A rollback
that has never been exercised is a plan, not a capability**, and the receipt is
what distinguishes the two.

### What closed since §16

- The three floating runtimes are **pinned by measurement**: Loki
  `sha256:73e905b5…`, Promtail `sha256:6cfa64ec…`, Grafana `sha256:0f86bada…`,
  read from the running containers' `RepoDigests`. The all-zero placeholders
  are gone, and they were load-bearing while they stood — an invalid digest
  fails at pull time, whereas a plausible wrong one promotes something.
- `routing/` is **populated**: receivers, policies and inhibition, transcribed
  from the live Alertmanager with one marked delta (explicit `warning` and
  `critical` routes to the receiver the fall-through already reached, which
  AGENTS.md rule 7 requires and which changes no alert's destination).
- The production tree therefore **loads end to end for the first time**, and
  `make production-check` runs the public gates over it in CI. Until `routing/`
  existed this was impossible: `load()` needs all three routing documents.

### One assumption still outstanding

`routing/receivers.toml` proposes `credential_ref = "telegram-oncall"` for the
single live Telegram binding. The private inventory was not readable when it
was written, so if it uses a different logical name, resolution fails with
`RESOLUTION-UNRESOLVED` at promotion. Flagged in the same shape and for the
same reason as `host.target_id` in `inventory/control-plane.toml`: a loud
failure at promotion, never a silent one.
