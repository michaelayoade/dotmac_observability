# dotmac_observability — hard rules

Canonical and tool-neutral. `README.md` explains the shape;
`docs/ARCHITECTURE.md` is as-built truth; `docs/adr/` holds decisions;
`docs/CONTROL_EXCEPTIONS.md` names every region that is declared **unmonitored**
rather than exempt. If this file and any other disagree, this file wins — fix
the drift.

Each rule names its enforcement. `enforcement: none yet (PR n)` is a stated
review discipline, not a guard, and it is a defect to describe it as enforced.

---

1. **Secrets are referenced, never stored.** Nothing in this repository may
   contain a token, password, webhook URL with an embedded key, bearer
   credential or certificate. An input declares an OpenBao path and the
   *logical file name* the evaluator will read; the value is host state placed
   by the deployment. Rendered configuration therefore contains
   `bearer_token_file: /etc/prometheus/secrets/<name>` and never a token.

   Since ADR-0004 that declaration lives in the PRIVATE inventory rather than
   in a committed document, because a store path and a basename are bindings
   even though neither is a value (rule 18). Rule 1 is unchanged and still
   necessary; what changed is where the reference is written down.
   — `tests/architecture/test_no_secret_material.py`

2. **No direct production file editing.** `/opt/observability` is not an
   editing surface. Every live byte is rendered here, staged as an immutable
   release directory and activated atomically. A change made on the host is
   drift to be reported and reverted, never a fix to be kept.
   — the COMPARISON exists (`src/dotmac_observability/drift.py`,
     `tests/unit/test_drift.py`), and nothing runs it against the live host,
     because reading the host is the promotion facility's job and that facility
     is not released. A detector nobody schedules is not enforcement.
     enforcement: `none yet (Foundation facility)`

3. **Every promotion targets an exact protected-main SHA**, reasserted as
   current at promotion time. A branch name, a tag alone or "latest" is not a
   promotion target. A repository-local claim is derived from repository-local
   facts; a claim that a bundle is published requires an external oracle
   carrying immutable coordinates (Governance ADR 0013).
   — the executor refuses a revision that is not an exact 40-character commit
     and one carrying no external oracle reference
     (`promote._preconditions`, `tests/unit/test_promotion_executor.py`), which
     is half of it. Nothing yet VERIFIES that the named oracle resolved
     protected main; the workflow holding that token is the only thing that
     can, and it cannot run until the facility exists.
     enforcement: `none yet (promotion lane)`

4. **Every bundle is immutable and digest-pinned.** A bundle lock names the
   product, environment, source revision, image digest, product-manifest
   digest, rules artifact pointer, `rules_sha256`, `metrics_manifest_sha256`
   and rule count. Promotion fetches the artifact and verifies the digest
   before anything is rendered. A version STRING is not an identity.
   — `contracts/bundle-lock.schema.json`; verification `none yet (PR 3C)`

5. **Product rules stay product-owned.** This repository pins and assembles;
   it never authors a product alert expression, and it never edits a fetched
   bundle. If a rule is wrong, the product repository fixes it and publishes a
   new bundle. A local patch would make one version name two contracts.
   — enforcement: `none yet (PR 3C)` (fetched bundles are byte-compared to their digest)

6. **Duplicate alert names, duplicate recording rules, or incompatible label
   vocabularies fail the build.** Two products may not both own `WorkerStalled`,
   and two bundles may not disagree about what `severity` can be.
   — enforcement: `none yet (PR 3C)`

7. **Every `warning` and `critical` route reaches a declared receiver**, or an
   explicitly reviewed null policy that says in words why this class of alert
   is deliberately not delivered. A route falling through to a default that
   nobody reads is the failure this rule exists to prevent.
   — `tests/unit/test_routing_coverage.py`

8. **Every rule carries an owner, a severity, a summary, a runbook and producer
   proof.** Producer proof means the alert's metric appears in the product's
   metrics manifest with a declared type, unit and bounded label vocabulary.
   Prometheus returning no series is not health — an alert over a metric nobody
   emits is permanently silent and indistinguishable from "all clear".
   — enforcement: `none yet (PR 3C)`

9. **Federated `up` and `scrape_*` series are renamed on import.** A central
   rule must never confuse an imported upstream's health with the health of a
   target this control plane owns. Every federation declares a rename prefix
   and the renderer emits the relabelling; a federation that does not rename is
   refused.
   — `tests/unit/test_federation_rename.py`

10. **"Rule inactive" is not recovery evidence.** Recovery requires that the
    rule EXISTS and is healthy, AND that its target is present and healthy. A
    deleted rule, a failed evaluation and a vanished target all present as
    "not firing". Any verification that accepts absence as success is wrong.
    — `src/dotmac_observability/live_verify.py` counts rules that EXIST and
      evaluate cleanly and reports a declared rule the evaluator did not load;
      an observation carrying no rules at all is refused rather than read as
      quiet. `tests/unit/test_live_verify.py`, and the sensitivity proof at
      `tests/mutations/test_live_verify_bites.py`, which shows the obvious
      version of each check reporting the same broken state as healthy.

11. **Promotion failure restores the exact preceding release.** The previous
    release pointer is preserved before activation and restored on any failure
    before `ACCEPTED`. There is no partial-promotion state an operator is
    expected to finish by hand.
    — `src/dotmac_observability/promote.py` captures the pointer at staging,
      refuses to continue when staging captured none, and rolls back on every
      failure from `STAGED` onward — including a failure at acceptance. A
      restore is recorded only when the facility returns a READ-BACK proving
      it; a command that returned is not a host that recovered.
      `tests/unit/test_promotion_executor.py`

12. **Desired state, live state and the last verified receipt are three
    independently comparable artifacts.** Drift is the disagreement between
    them. A design that can only read one of the three cannot detect drift.
    — all three are now artifacts: the desired state renders to a tree digest,
      the receipt has `contracts/promotion-receipt.schema.json`, and live state
      has `contracts/live-observation.schema.json` rather than being a habit of
      reading APIs in the right order. `drift.compare` reports which PAIR
      disagrees, and reports `DRIFT-INCOMPARABLE` rather than presenting a
      two-artifact answer as a three-artifact one.
      `src/dotmac_observability/drift.py`, `tests/unit/test_drift.py`

13. **Rendered bytes are committed, never hand-edited, and deterministic.**
    `make render-check` re-renders every declared inventory and compares
    BYTES. Same inputs, same bytes, on any machine, in any order — no
    timestamps, no hostnames, no set iteration, no locale.
    — `tests/unit/test_render_determinism.py`, `make render-check`

14. **Everything by config.** Every environment-specific value is an
    overridable knob with a documented default (Make `?=`, compose
    `${VAR:-default}`, `: "${VAR:=default}"`). Never hardcode a host, port,
    image, path or retention.
    — `tests/architecture/test_repository_contract.py`

15. **A guard exemption states an ENFORCEABLE premise** (Starter ADR-0018).
    A region with no guard is recorded in `docs/CONTROL_EXCEPTIONS.md` as
    unmonitored, with the PR that will monitor it. "Grandfathered" and
    "reviewed and correct" stay distinct, and every detector carries a
    sensitivity proof — a check that cannot demonstrate it bites is not
    enforcement.
    — `tests/mutations/`, `tests/architecture/test_control_exceptions.py`

16. **Cross-repository engineering governance is pinned by exact commit**, and
    the workflow executes that same accepted revision.
    — `.dotmac/standards-profile.json`, `.github/workflows/engineering-standards.yml`

17. **Branch before committing; never commit to `main`.** Merge only on green.
    Only an explicitly authorized promotion touches a live host, and the target
    may be named directly or resolved from the authoritative fleet inventory
    when the authorizing request permits that resolution. Verify the reached
    host's identity against the inventory before any mutation.
    — branch protection on `main`: linear history required, force-push and
      deletion refused, every change through a pull request

18. **This repository is PUBLIC**, and that is a deliberate trade (ADR 0003).
    Branch protection and CI minutes are both unavailable to a private
    repository on this account's plan, so the alternative was an unprotected
    `main` with no CI at all.

    Everything committed here is world-readable the moment it lands, and Git
    history is not retractable. Rule 1 keeps secret VALUES out; public
    visibility asks a second question rule 1 does not answer, and ADR 0004
    answers it: **public Git carries the LOGICAL description, private
    inventory carries the resolved material.**

    Public: logical target ID (`erp-production`), service owner and
    environment, metric and alert contracts, expected capabilities, scrape
    protocol, health semantics, bundle and inventory schema, synthetic CI
    endpoints, and the private inventory's version and digest. Private:
    resolved hostname or IP, port and complete scrape URL, TLS and server
    identity, credential-file binding (`openbao_path` included), federation
    endpoint, network-route details — held under an approved OpenBao
    deployment-inventory path or another explicitly owned private source.

    Promotion resolves the logical target, validates it against the public
    schema, renders deterministically, records the private inventory's version
    and digest — never its values — in the receipt, and compares drift by
    digest without printing an endpoint. A production endpoint published
    deliberately requires a per-target exception block carrying a rationale
    and a named approver; cleartext is never the default and never an
    omission.

    Enforced in two independent ways, because either alone has a blind spot.
    STRUCTURALLY: the public contracts close every object and have no field an
    endpoint, a port, a credential binding or a destination can be typed into,
    so the per-target exception is available only through a block that also
    demands a rationale and a named approver. BY SCAN: a detector over every
    tracked file refuses a resolved address, a real subdomain or a store path
    in prose, a comment, a workflow or a rendered artefact — where no schema is
    looking, and where both of this repository's actual disclosures happened.
    — `tests/architecture/test_public_inventory_carries_no_private_material.py`,
      `tests/mutations/test_private_material_detector_bites.py`,
      `tests/architecture/test_no_secret_material.py`, `make private-scan`;
      structurally, `contracts/target.schema.json`,
      `contracts/control-plane.schema.json`, `contracts/routing.schema.json`

19. **Every published surface declares its exposure and its address family.**
    Exposure (`none`, `loopback`, `ingress`, `public`) and address family
    (`ipv4`, `ipv6`, `dual_stack`) are both mandatory, with no default: an
    undeclared value is a refusal, never an inferred one, because a default is
    how a wildcard bind reached a second address family unnoticed and left the
    firewall rules written for it in a chain the traffic never traverses
    (ADR-0005, `docs/inventories/observer-as-built.md` §9.1). A bare
    `PORT:PORT` publish is refused, an unauthenticated `public` surface is
    refused, and a backend that declares `ingress` may not also publish a host
    port. The vocabulary and its rendering belong to
    `dotmac-deployment-foundation`'s `IngressPolicy.v1`; this repository adopts
    it and owns only which surfaces are declared and how they are promoted. A
    resolved address, port, DNS record, certificate identity or credential
    binding never appears in public Git (rule 18).
    — enforcement: `none yet (Foundation adoption)`

20. **This repository AUTHORIZES nothing, and never attests an approval to
    itself.** It is the first adopter of the deployment control plane, not a
    second one. `dotmac-deployment-control` owns deployment intent, plan
    freezing, approval policy and the approval decision; this repository
    consumes an approved plan and records WHICH plan it executed — a
    `plan_digest` and an `approval_decision_ref` resolvable in the system that
    took the decision.

    No contract here may define approval or signature semantics, and none may
    carry a self-attested approver: a name typed into a tracked file is
    verified by nothing, notifies nobody, and manufactures the appearance of an
    approval record where there is none. Where this repository genuinely needs
    a human decision on the record — the per-target publication exception — it
    keeps the RATIONALE, which a reviewer can disagree with, and leaves the
    approval to the protected-branch merge, which is externally attested and
    carries immutable coordinates (Governance ADR 0013).
    — `tests/architecture/test_authorization_is_not_owned_here.py`

21. **A private inventory version is SUPERSEDED, never overwritten.** Writing a
    new version names the digest of the version it replaces, and the write is
    refused when that digest is not what the store currently holds. The
    succession is checked as a whole: same document, same environment, version
    exactly one higher, and something actually changed.

    Compare-and-set rather than a blind write, because the failure it prevents
    leaves no trace. Two operators read version 1, each edits it, each writes
    version 2; the second write wins and the first one's change — a
    decommissioned product's target removed, say — is back in the environment
    with nothing anywhere recording that it ever left. The next promotion
    resolves it and scrapes a host that no longer exists.

    A digest printed after a write does not catch this: it proves the writer
    can hash what it is holding. Reading the stored bytes back and comparing
    them against the digest that was meant to be stored is the half that can
    fail on a partial write, so `inventory-digest --expect` exists and a
    supersession is not complete without it. The superseded version is
    RETAINED: it is the evidence for every receipt that names it.

    **The workflow is the writer, and the change is a reviewed request.** A
    hand-run supersession is the unversioned, unreproducible edit this
    repository exists to remove, so `.github/workflows/private-inventory-supersede.yml`
    performs the write, from protected `main` only, applying a
    `supersession-request` merged after review. Nothing it emits is the
    document: not a log line, not a job summary, not an artifact, and not on
    the failure path — where a handler added to explain a failure is the one
    that publishes the thing. A request can only RETIRE, because retiring needs
    a logical name while provisioning needs a resolved value that must not
    enter public Git or a CI input.

    Three properties of WHERE it runs and WITH WHAT, each of which was a defect
    in an earlier draft. It runs on a NAMED fixed-egress runner, never a hosted
    one, because the store's listener is contained behind an allowlist and
    widening that to reach a dynamic range would undo the containment to serve
    a convenience. The credential lives in the steps that touch the store and
    nowhere above them, because a job-level `env` hands a production token to
    checkout, the setup actions and everything `poetry install` executes. And
    READING and WRITING are separate path-scoped identities: discovery needs no
    write capability at all, the writer needs no list capability, and one
    identity able to do both is the thing to eliminate.

    The storage shape is CONFIRMED against the reviewed request, never
    discovered and acted on in the same run. Discovery is its own read-only
    workflow that reports and stops, with a human in between — a shape detected
    and immediately written is a probe whose result nobody reviewed.
    — `tests/unit/test_private_inventory_supersede.py`,
      `tests/unit/test_supersession_request.py`,
      `tests/architecture/test_supersession_workflow_cannot_leak.py`

22. **One bundle, rendered whole.** Everything the control plane deploys is one
    `observability-bundle.v1` and one render: the evaluators, the log store and
    shipper, dashboard provisioning, the Observer-owned syslog and rotation
    contract, the declared infrastructure timezone, the roster of owned
    resources, the retired-product list, the exposure policy and the
    verification gates. A promotion that can activate a subset is a promotion
    that can leave the host in a combination nobody described. The bundle holds
    no topology and no credentials: a source is a named typed set bound
    privately, a datasource URL is derived from the roster.
    — `contracts/bundle.schema.json`, `tests/unit/test_bundle.py`,
      `tests/mutations/test_bundle_gates_bite.py` (ADR-0008)

23. **A published surface's chain is DERIVED from its kind and address family,
    never chosen.** An IPv4 container publish is forwarded and traverses
    `DOCKER-USER`; an IPv6 one terminates on `INPUT`. Seven IPv6 DROP rules were
    found in `DOCKER-USER` on this host, where no such packet arrives, so every
    port they name reads as closed and is open. This is `iptables` — `-i`, not
    nftables' `iifname`. And **persistence is not authorship**: `netfilter-persistent
    save` snapshots live state wholesale, so a rule surviving reboot says
    nothing about who created it.
    — `tests/unit/test_bundle.py`, `tests/mutations/test_bundle_gates_bite.py`

24. **Target health and ingestion integrity are separate facts, and a gate
    carries both.** `up == 1` says the scrape completed; it says nothing about
    whether the samples were stored. Eighteen of eighteen targets read green on
    this host while 1,858,942 samples were rejected. A verification gate
    declares a `health` predicate AND an `integrity` predicate and the renderer
    emits their conjunction; a gate whose two predicates are the same, or whose
    integrity predicate names no ingestion counter, is refused.
    — `contracts/bundle.schema.json`, `tests/unit/test_bundle.py`

25. **A log file's owner, group and mode are DECLARED, and something other than
    the privilege-dropped writer creates it.** rsyslog runs as `syslog` and
    `/var/log` is `root:syslog 0755`, so it can append to a file it owns and
    cannot create one; `/var/log/mail.log` did not exist and one action
    suspended 10,161 times in thirty days while the mail facility went nowhere.
    The directory is NOT widened. systemd-tmpfiles creates the file as root
    with the declared ownership, logrotate recreates it the same way with an
    explicit `create <mode> <owner> <group>`, and `postrotate` reopens the
    writer rather than `copytruncate` losing what falls between the copy and
    the truncate.
    — `tests/unit/test_bundle.py`, `scripts/rotation_proof.py` run by CI's
      `rotation-proof` job, whose three negative controls must each fail

26. **A retired product stays retired, and the check is standing rather than a
    sweep.** A retirement declares every spelling the product was known by, and
    a rendered tree mentioning one fails the render. Over RENDERED bytes, for
    two reasons: it covers every surface the bundle produces rather than the
    subset somebody thought to search, and it cannot read nothing — a sweep
    over a tree it failed to load reports "no references" exactly as a clean
    one does, and an item recorded UNKNOWN twice starts being read as absent.
    — `contracts/bundle.schema.json`, `tests/unit/test_bundle.py`

27. **A stored private document is CLASSIFIED before it is loaded.** Both
    mutation tools validate the previous version against the accepted contract
    as their first act, so a store holding the pre-contract capture format
    fails with 68 schema errors in a tool whose job is to print a digest —
    after the precondition guard has passed. A capture is migrated by a
    reviewed `migrate-capture` request whose every produced byte comes from the
    store; the one field the capture lacks, the host binding, arrives as a
    repository secret in the single step that needs it. Migrating changes the
    document's digest, which is the compare-and-set precondition, so a request
    naming the pre-migration digest is refused afterwards — correctly, and the
    refusal names `inventory-classify` as how to tell that from a lost update.
    — `contracts/private-inventory-capture.schema.json`,
      `tests/unit/test_capture_migration.py`,
      `tests/architecture/test_supersession_workflow_cannot_leak.py` (ADR-0008)

28. **The CI matrix equals `make check`'s prerequisites exactly.** A matrix
    naming a subset is a documented past failure on this fleet: the gate keeps
    passing locally while nothing enforces it on a pull request. Previously a
    comment; now enforced.
    — `tests/architecture/test_ci_matches_the_makefile.py`

29. **`rendered_guarded` is not `deployed_repaired`.** A defect closed in the
    renderer is unrepresentable in newly rendered bundles, which is durable and
    real — and it is not a repair, because the host is not yet running a
    rendered bundle. The second verdict requires all six of: the control plane
    authorizes the exact bundle digest; Foundation applies those exact bytes;
    live read-back matches the whole rendered tree, compared rather than
    sampled; every target healthy AND zero new rejected samples against a
    RECORDED baseline; the live probes pass on BOTH address families with a
    positive control in the same pass; and rollback restores the prior digest
    and produces a receipt. Claiming the second while holding the first is the
    error this vocabulary exists to prevent.
    — `docs/inventories/observer-as-built.md` §17

30. **An integrity predicate is DELTA-SHAPED, and the counter is never reset.**
    `<counter> == 0` is satisfiable by resetting the counter, by a fresh TSDB
    or by a container restart, and a predicate made true that way cannot be
    told from one made true by a repair. The counter on this host stands at
    1,864,926 historical rejections and must stay visible; what is asserted is
    that it does not grow from a recorded baseline.
    — `GATE-INTEGRITY-NOT-DELTA`, `tests/unit/test_bundle.py`

31. **A job that cannot run must FAIL, never queue.** A job pinned to an absent
    or offline runner queues indefinitely — `timeout-minutes` bounds execution,
    not queueing — so an operator learns nothing. Availability is established
    BEFORE the queue by a job that can always execute, which the mutation
    `needs:`; a failed precondition skips the dependent job instead of queueing
    it. The check fails closed when it cannot read the runner list, because an
    unverifiable precondition is not a satisfied one. It is hosted precisely so
    it can run when the named runner cannot. It may hold only a repository-
    scoped `RUNNER_QUERY_TOKEN`, never an OpenBao or inventory credential; the
    diagnostic proves that identity receives 200 on this repository and 403 on
    the foreign control-runner repository before a job with no user-provisioned
    repository secret acquires the exact repository-specific runner identity
    and label set.
    — `tests/architecture/test_supersession_workflow_cannot_leak.py`,
      `tests/architecture/test_control_runner_diagnostic.py`

32. **No workflow may execute fork-controlled content on these runners.**
    `pull_request_target` runs trusted base-branch workflow code with a
    write-capable context against a fork's head, which is exactly why it
    bypasses the fork-workflow approval gate — and the repository-wide
    `all_external_contributors` setting does not cover it. Refused
    repository-wide rather than only where a credential lives today, because
    the same runners serve every workflow and a job can be given a secret
    tomorrow. Checking out `pull_request.head.sha` under that trigger is the
    shape that turns it into arbitrary code execution, and is refused by name.
    — `tests/architecture/test_ci_matches_the_makefile.py`,
      `tests/architecture/test_supersession_workflow_cannot_leak.py`

33. **The ingestion boundary is a versioned contract, and a field accepted
    without validation is a field nobody owns.**
    `observability-telemetry-ingestion.v1` declares the resource identity every
    record carries, the accepted attribute vocabulary and what each attribute
    is validated against, which attributes may become stream labels, and what
    is refused. Anything not named is not accepted: an open vocabulary at the
    boundary is how a store acquires an index dimension with a million values
    and how a header nobody meant to ship becomes permanently searchable, and a
    store cannot un-receive a credential.

    Every rejection rule carries planted material the LOADER runs the
    classifier over, and the gate compares the rule NAME rather than the
    outcome — a probe refused by the vocabulary check instead would leave its
    rule inert while every assertion still passed. The negative suite carries
    positive controls in the same document, because a classifier that refuses
    everything satisfies every rejection probe ever written and only a control
    record can tell the two apart. Planted material is BUILT rather than
    committed, so proving that credential-shaped strings are refused never
    requires committing one.
    — `contracts/telemetry-ingestion.schema.json`,
      `src/dotmac_observability/ingestion.py`, `validate._ingestion_findings`,
      `tests/unit/test_ingestion.py`,
      `tests/mutations/test_ingestion_gates_bite.py` (ADR-0011).
      What is NOT enforced is the RUNTIME application: the policy is complete
      and proved against planted material, and nothing applies it to bytes on
      the wire, because no ingestion-edge stage is deployed. Calling the
      rejection enforced in production would be the overclaim rule 29 exists to
      prevent. enforcement of the runtime half: `none yet (ingestion-edge lane)`

34. **Dropped, never sent and never measured are three facts, and silence is
    detected by ABSENCE.** A drop counter reading zero because nothing was
    shipped and one reading zero because nothing was lost are the same number
    and opposite news, so every stream declares a separate arrival counter and
    integrity counter and the renderer emits `<Signal>IntegrityUnmeasured`
    beside `<Signal>IngestionDropping`. `UNMEASURED` is a verdict, never a
    missing value: a counter never observed, a baseline never recorded and a
    counter that went backwards under a reset are all unmeasured rather than
    stable.

    Silence is `absent_over_time`, never a rate threshold. The two read like
    the same question: when a shipper stops its series stops existing, and
    `rate(x[5m]) == 0` over a series that does not exist matches no rows and
    fires nothing at all. A stream whose lag nothing measures renders NO lag
    alert and declares `lag_unmeasured` with a rationale and an owner — naming
    a plausible metric instead renders a rule that can never fire, which reads
    on every dashboard exactly like one quietly passing (rule 8 by another
    route).
    — `ingestion.integrity_state`, `render._ingestion_rules`,
      `tests/mutations/test_ingestion_gates_bite.py`, whose second half writes
      the obvious version of each check and shows it reporting the fault as
      healthy

35. **A deadman that has never fired is not known to work.** Each one declares
    the planted condition that makes it fire, where the procedure is written,
    and the date it was last observed to fire — or the literal `never`, which
    is counted by a two-directional ratchet and stamped into the rendered
    alert's own annotations. An unproved deadman is indistinguishable from one
    whose expression matches no series at all, and the moment that matters is
    the moment somebody is relying on it. A `procedure_ref` resolves to a
    tracked file or the build fails: a dangling reference in an alert is
    discovered during an incident and costs its first minutes.

    A deadman is control-plane meta only. Assembly is not authorship (rule 5),
    and an expression naming neither a series this contract declares nor a
    control-plane series is a product's alert wearing a deadman's name.
    — `validate._ingestion_findings` (`DEADMAN-UNPROVED-COUNT`,
      `DEADMAN-NOT-META`), `tests/architecture/test_ingestion_procedures.py`,
      `tests/mutations/test_ingestion_gates_bite.py`

36. **The audit projection is never authoritative, and `rebuildable` is proved
    rather than asserted.** The evidence is the audit row a product writes in
    the same transaction as the decision, in its own database; a central
    projection exists so the fleet can be searched. `authoritative` is a
    `const false`, so no document can express the other value — a projection
    that CAN be declared authoritative eventually is, usually in the hour when
    the application database is the thing that is down.

    Its retention is bounded from ABOVE by its source's, because a projection
    retained longer than the rows it derives from becomes the last copy of one,
    and a last copy is authoritative whatever any document says. It cannot
    claim a rebuild that never ran — `last_rebuilt: never` admits only
    `UNMEASURED` — and the ratchet runs the other way too, so a completed proof
    is recorded rather than left looking outstanding. The lag alert's own text
    says the projection is not authoritative and NAMES what is, because an
    operator told only the first goes looking, and what they find will be
    another projection. A comparison against a side that could not be read, or
    between two empty sides, is `UNMEASURED` and never agreement.
    — `contracts/telemetry-ingestion.schema.json`,
      `ingestion.compare_rebuild`, `validate._ingestion_findings`
      (`PROJECTION-OUTLIVES-SOURCE`, `REBUILD-OVERCLAIMED`,
      `REBUILD-UNDERCLAIMED`, `PROJECTION-NOTICE-NO-SOURCE`),
      `tests/unit/test_ingestion.py`

---

## The line this repository must not cross

It is tempting, once a repository owns the evaluator, to let it own the alert
too — to "just fix" a threshold centrally. Doing so silently moves a product
decision out of the product, and the product's tests then prove something the
fleet no longer runs. Assembly is not authorship. The only alert expressions
this repository may contain are its own control-plane meta-alerts (deadman,
evaluator health, bundle-digest mismatch), which it genuinely owns because no
product can observe them.
