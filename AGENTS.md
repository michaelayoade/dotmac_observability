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
   — enforcement: drift detection, `none yet (PR 6)`

3. **Every promotion targets an exact protected-main SHA**, reasserted as
   current at promotion time. A branch name, a tag alone or "latest" is not a
   promotion target. A repository-local claim is derived from repository-local
   facts; a claim that a bundle is published requires an external oracle
   carrying immutable coordinates (Governance ADR 0013).
   — enforcement: `none yet (PR 6)`

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
    — enforcement: `none yet (PR 5)`

11. **Promotion failure restores the exact preceding release.** The previous
    release pointer is preserved before activation and restored on any failure
    before `ACCEPTED`. There is no partial-promotion state an operator is
    expected to finish by hand.
    — enforcement: `none yet (PR 6)`

12. **Desired state, live state and the last verified receipt are three
    independently comparable artifacts.** Drift is the disagreement between
    them. A design that can only read one of the three cannot detect drift.
    — enforcement: `none yet (PR 6)`

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
    host must be named by a human in the authorizing request — never inferred
    from an inventory row.
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

---

## The line this repository must not cross

It is tempting, once a repository owns the evaluator, to let it own the alert
too — to "just fix" a threshold centrally. Doing so silently moves a product
decision out of the product, and the product's tests then prove something the
fleet no longer runs. Assembly is not authorship. The only alert expressions
this repository may contain are its own control-plane meta-alerts (deadman,
evaluator health, bundle-digest mismatch), which it genuinely owns because no
product can observe them.
