# ADR-0005: Declared exposure and address family

- **Status:** Accepted
- **Date:** 2026-08-29
- **Supersedes:** nothing
- **Related:** `docs/adr/0003-the-control-plane-repository-is-public.md`,
  `docs/adr/0004-public-logical-inventory-private-promotion-material.md`,
  `AGENTS.md` rules 14, 18 and 19, `docs/SECURITY.md`,
  `docs/inventories/observer-as-built.md` §9.1

## Context

Finding OBS-07 in the Observer census was recorded, withdrawn and re-recorded.
The corrected form (§9.1) is narrower than the original and considerably worse,
and the mechanism behind it is the reason this ADR exists.

**What was measured.** IPv4 containment on the Observer host is real: 198 rules
in the IPv4 `DOCKER-USER` chain, nine blocks covering the observability ports,
byte-identical to the persisted `rules.v4`, with packet counters showing about
a fortnight of work, and `iptables-persistent` enabled so the restriction
survives a reboot. The IPv6 rules written for the same ports sit in the
`ip6tables` `DOCKER-USER` chain. Every one of them shows a zero packet counter.
That is not the signature of a rule nobody has exercised; it is the signature
of a rule nothing can reach.

**Why it cannot fire.** A Compose short-form publish of the shape `PORT:PORT`
names no bind address, so the daemon binds the wildcard on both address
families and starts one `docker-proxy` process per family. With no IPv6 DNAT in
play, the IPv6 `docker-proxy` terminates the connection as an ordinary local
process: the packet is delivered to the host, arrives on `INPUT`, and never
traverses `FORWARD`. `DOCKER-USER` is jumped only from `FORWARD`. The rules
therefore sit in a chain the traffic they were written for does not pass
through. This was verified rather than inferred — probes from two other fleet
hosts found the affected ports open over IPv6, with a port known to be closed
used as a discriminating control, and a third probe from a host with no global
IPv6 was discarded precisely because it failed the control and would otherwise
have read as a false pass.

**Why nobody noticed.** This is the part that matters more than the chain
mechanics, because the chain mechanics are one host's misconfiguration and this
is a design defect. Nothing in the system ever had to *declare* which address
families a surface meant to expose. Exposure was a side effect of a two-number
string in a Compose file, the second family was created silently, and the
firewall work that followed was written against the family somebody had in
mind rather than against the families that actually existed. There was no
document to review, no field to disagree with, and no gate that could compare
an intent against an observed listener, because no intent had ever been
written down. A defect that is invisible in the inputs cannot be caught in
review, and a defect nothing renders cannot be caught by a byte gate.

**The second, larger property.** Even where the firewall rules do fire, the
posture they produce is a single boundary. IPv4 `DOCKER-USER` allowlisting is
the only thing between a remote log shipper and Loki's ingestion API; the API
itself accepts whatever reaches it. One chain, one persistence file, one sweep,
and no second line. The census records that the same inert IPv6 idiom was
applied fleet-wide in the 2026-08-14 sweep, which is the concrete demonstration
that a firewall-only posture fails silently and fails in bulk.

**What constrains the remedy.** Three facts from the same preflight bound the
solution space, and each is load-bearing:

- **`INPUT` filtering is blocked, not merely awkward.** The correct place for a
  rule against a locally-terminated connection is `INPUT`, and an `INPUT` rule
  carries SSH. Out-of-band recovery on this host is present but unproven: a
  provider console and a serial getty exist, but no working root password was
  confirmed. Editing `INPUT` without proven recovery risks locking the estate
  out of its own observability host.
- **Loki cannot be loopback-bound.** It has six live remote log shippers. Every
  other affected service — Prometheus, Alertmanager, node-exporter, cAdvisor —
  is reached only by this host's own Prometheus, over the container bridge and
  by container name, so unpublishing those breaks nothing at all.
- **Source allowlists must be derived from observed addresses, not from DNS.**
  One shipper's hostname resolves to an address that was never seen connecting;
  it arrives from a different address in the same autonomous system. Narrowing
  to DNS-derived addresses would have cut it off.

The third fact is the one that decides the architecture rather than merely
complicating it. If an allowlist entry cannot be derived from the name of the
thing it is meant to admit, then the allowlist is not identifying a shipper. It
is identifying a network position that a shipper currently happens to occupy.

**Why this is not a boundary this repository should invent.** Nothing above is
specific to observability. A declared exposure, a declared address family, an
authenticated front on 443 and a conformance suite that compares observed
listeners against a declaration are wanted by every Dotmac deployment that
publishes anything. A control plane that solved it locally would produce a
second implementation of a facility that already exists to hold this class of
mechanics, and the fleet would then have two answers to the same question with
no way to keep them agreeing.

## Ownership

Michael has ruled the split, and it is recorded here because the rest of this
ADR only makes sense against it.

- **`dotmac-deployment-foundation` owns the reusable contract**, named
  `IngressPolicy.v1`, together with its validation, its deterministic Compose
  and Nginx rendering, its conformance suite and its rehearsal. The facility
  lives in `dotmac_starter_mt` and is released; it is not vendored, forked or
  reimplemented here.
- **Nginx is the first provider, and is not embedded in the contract.** The
  policy describes an ingress; it does not describe Nginx. A second provider
  must be addable without a contract change.
- **`dotmac_observability` is the first adopter.** It owns Loki-specific
  selection — which surfaces are declared, with what exposure and which
  families — and the promotion, receipts, rollback and drift detection that
  carry those declarations to the Observer host. It owns no ingress mechanics.
- **OpenBao holds the resolved material**: addresses, ports, certificates and
  credentials. That is the same custody boundary ADR-0004 already draws, applied
  to a wider set of fields.
- **The kernel and the stateful modules own none of this.** Ingress is a
  deployment concern, not an in-process one.

## Decision

**This repository adopts the Foundation-owned `IngressPolicy.v1` vocabulary
rather than defining its own.** It declares an exposure and an address family
for every published surface, and it keeps the Loki-specific selection and
promotion. Both fields are mandatory, neither has a default, and an undeclared
value is a refusal rather than an inferred one. Loki ingestion moves behind the
Foundation's authenticated ingress on 443, and that ingress becomes the one way
any service in this control plane is reachable from outside the host.

### The vocabulary this repository needs

The two vocabularies below are the shape this control plane needs and will
consume. They are a **proposal to the Foundation, not a settled local
contract**: the authoritative names, spellings and defaults land with the
`IngressPolicy.v1` release, and if the released contract names a value
differently, the released contract wins and this section is what gets
corrected. Nothing here is a licence to define the vocabulary locally in the
meantime.

**Exposure** — a closed four-value vocabulary:

| Value | Means |
| --- | --- |
| `none` | Not published. Reachable only on the container network, by container name. |
| `loopback` | Published on loopback only. Reaching it is an explicit act — an SSH tunnel, or a proxy the host owns. |
| `ingress` | Not published directly. Reachable only through the declared authenticated ingress. |
| `public` | Published to a network beyond the host. Requires an explicit reviewed exception **and** authentication. Both, not either. |

**Address family** — a closed three-value vocabulary: `ipv4`, `ipv6`,
`dual_stack`.

**Declared, never defaulted.** This is the direct answer to the mechanism in
the Context. A default — any default, including the apparently safe choice of
IPv4 — is how the wildcard bind got published unnoticed in the first place: the
document said nothing, the runtime did something, and the two were never
compared because there was nothing to compare against. A declaration makes the
intent reviewable before it renders, makes the rendered bytes a consequence of
a stated decision rather than of a library's defaults, and gives conformance
something to check an observed listener against. An address family that is
inferred is an address family nobody has to agree with.

### What this repository selects

Prometheus, Alertmanager, node-exporter, cAdvisor and **raw** Loki are
internal-only: `none`, or `loopback` where an operator genuinely needs a local
port. Loki *ingestion* is `ingress`, dual-stack, with per-shipper mTLS or
per-shipper credentials. Nothing in this control plane is `public` today, and
the value exists so that a future one has to argue for itself in a reviewed
block rather than arrive as an omission.

Per-shipper is the load-bearing word. Six shippers means six credentials, and
the property being bought is that one of them can be revoked without touching
the other five — which is precisely what an address allowlist cannot do.

### What is rejected

Six refusals. Each is a hard failure in validation or rendering, not a warning,
and the first three are the ones the Context measured:

1. **Bare Compose port syntax.** The short form is exactly the construct that
   creates a family nobody declared.
2. **Implicit address families.** An undeclared family is refused; it is never
   filled in.
3. **Public ingestion without declared TLS and authentication.** `public` and
   authenticated are one decision, not two fields that can drift apart. An
   exception block governs publication; it does not excuse the absence of a
   boundary.
4. **A publicly reachable backend behind an ingress.** A service that declares
   `ingress` and also publishes a host port has an ingress in front of it and a
   door beside it. The ingress is then decoration, and every property proved
   about it is proved about a path an attacker need not take.
5. **Product or provider branches.** No `if loki`, no `if nginx`, anywhere in
   the shared facility. A branch on the product being fronted or the provider
   doing the fronting is the first copy of an implementation, and the second one
   follows.
6. **Resolved production material committed to the public repository.**
   Addresses, ports, DNS specifics, certificate identities and credential
   bindings stay in OpenBao. This is ADR-0004 unchanged, extended to the fields
   this decision adds.

### The wider contract is Foundation's, not this ADR's

Exposure and address family are the two fields this repository needs most, and
they are not the whole of `IngressPolicy.v1`. The Foundation contract also has
to carry source policy, connection and body limits, timeouts, rate limiting,
health checking, telemetry, rollback semantics, and the bindings by which
private promotion material is resolved into a rendered listener. Those are in
the Foundation's scope and are named here so this ADR is not read as a claim
that a two-field policy is sufficient. This repository consumes them; it does
not specify them.

### The IPv4-bind proposal is emergency containment, not this architecture

An earlier proposal was to bind Loki to an explicit IPv4 address, so that the
existing, working IPv4 `DOCKER-USER` allowlist covers it and the unreachable
IPv6 rules stop mattering. That is a legitimate thing to do in an hour when the
alternative is leaving an unauthenticated ingestion API open over IPv6. It is
**emergency containment only, and explicitly not the final architecture**, for
three reasons that do not improve with time:

1. **An address allowlist authenticates a network position, not a shipper.**
   It admits whoever currently occupies an address. Nothing about the traffic
   proves which shipper sent it, so nothing about the boundary can attribute a
   write to a sender.
2. **It cannot revoke one shipper without disturbing the others.** Removing an
   allowlist entry removes a network position, and positions are shared:
   several shippers can sit behind one NAT egress. The blast radius of a
   revocation is whoever happens to share the address, which makes revocation
   an operation nobody wants to perform.
3. **It breaks when a NAT egress address changes, which this fleet has already
   observed.** The census records a shipper whose DNS name resolves to an
   address that never connects, arriving instead from a different address in
   the same autonomous system. An allowlist maintained against a moving egress
   address is a source of outages, and each outage is repaired by widening the
   allowlist.

And underneath all three: it leaves ingestion **unauthenticated on the wire**.
The bytes crossing the network carry no credential and no transport identity,
so the boundary is the packet filter and only the packet filter.

### The argument this decision actually rests on

**This stops host firewall rules being the sole security boundary.**

That is not a preference for defence in depth as a slogan. It follows from the
specific position this host is in. The correct firewall fix — `INPUT`
filtering — is blocked on out-of-band recovery that has not been proven, and
proving it requires physical-adjacent access this repository does not control
and cannot schedule. Meanwhile the boundary that does exist is one chain, whose
IPv6 half has been demonstrably inert for a fortnight, produced by a sweep that
applied the same inert idiom across the fleet.

An authenticated ingress can be built, rendered, byte-compared and rehearsed on
a disposable host **without** touching `INPUT` and without waiting for the
recovery path. It is the part of the remedy that is not blocked. When `INPUT`
hardening does become safe, it lands as a second line behind a boundary that
already authenticates, rather than as the first and only one.

## Consequences

### What changes in this repository

- **Two new mandatory fields on every published surface**, consumed from
  `IngressPolicy.v1` and carried through this repository's inventory documents,
  its typed model and its promotion receipts. There is no migration period in
  which a surface may omit them: a document without both fails validation.
- **Short-form publishes disappear from the rendered output.** Every publish is
  an explicit bind per declared family, derived from the declared exposure and
  the privately-resolved address. `none` renders no publish at all.
- **A new component in the deployed stack**, rendered by the Foundation and
  promoted by this repository on the same terms as everything else (ADR-0002):
  committed bytes where they are this repository's bytes, directory mounts,
  digest-pinned images, atomic activation, and a receipt that records what ran.
- **Conformance runs against real Compose**, not against a description of
  Compose, and it is the Foundation's suite rather than a local one. Six
  properties, each demonstrated rather than asserted: IPv4 ingestion succeeds;
  IPv6 ingestion succeeds; an unauthenticated request is refused; a revoked
  credential is refused; a shipper recovers after a legitimate credential is
  restored; and the listeners the running stack actually opens match the
  families the policy declared. The last is the one that would have caught
  OBS-07, and it is the reason the family is a declared field rather than a
  rendering detail.
- **`AGENTS.md` gains rule 19**, with the enforcement line
  `none yet (Foundation adoption)`. The guard lives in the released facility
  rather than in a local pull request, so rule 19 becomes enforced here when
  this repository adopts a Foundation release that carries it — not when a PR
  in this repository merges. Until then it is stated review discipline, and
  describing it as enforced is a defect (rule 15).

### Build once

The test of whether the split above was worth making is a single sentence, and
it is worth quoting because it is the acceptance criterion for the Foundation
work rather than a sentiment about reuse:

> The same released facility must serve Loki ingestion, OTLP, webhook ingress
> and ordinary product HTTP edges through policy alone, without copying
> implementation.

Every rejection in the list above follows from it. A provider branch, a product
branch, or a field that only makes sense for one of those four workloads is a
copy waiting to happen, and the copy is what stops the fifth adopter from
getting the fixes the first four paid for.

### The phased cutover

Six phases. No phase may start before its predecessor has produced evidence,
and phases 2 onward touch a live host and therefore require a human to name
that host in the authorizing request (rule 17).

1. **Build.** Dual-stack contracts, renderer support and the ingress itself,
   with the conformance suite green against real Compose on a disposable host.
   Nothing on Observer changes. This phase is Foundation work; this
   repository's part is the adoption lane described in
   `docs/ARCHITECTURE.md` §"Delivery train".
2. **Activate IPv4 and migrate.** Bring up authenticated IPv4 ingestion and
   move all six shippers off raw Loki onto it, one at a time.
3. **Prove.** Delivery, per-shipper attribution and rollback, for each migrated
   shipper. A shipper is not migrated until its logs are shown arriving through
   the ingress and attributable to its own credential.
4. **Add IPv6.** Publish AAAA records and activate the IPv6 listener. The IPv6
   conformance rules written in phase 1 remain inert until this point, and are
   knowingly inert rather than accidentally so.
5. **Prove independently.** IPv4 ingestion and IPv6 ingestion each verified on
   their own, not as a pair that passes because one of them works. A dual-stack
   test that cannot fail one family is the same class of check as the rules in
   §9.1.
6. **Remove.** Withdraw the raw Loki publication and delete the inert IPv6
   firewall rules. Only here does the old path stop existing.

Phases 2 to 6 are operational steps against the Observer host, sequenced after
PR 5's rehearsal capability exists, and each separately authorized; none is
assigned a numbered PR here, because assigning one would imply a schedule that
has not been agreed.

### The honest cost

**An ingress is a new component with its own failure mode.** Today, a shipper
talks to Loki. Afterwards, a shipper talks to an ingress that talks to Loki,
and the ingress can be down while Loki is up. It terminates TLS, so a
certificate can expire; it holds per-shipper credentials, so those credentials
have to be issued, distributed and rotated, and a rotation that is botched
stops a shipper as effectively as a firewall rule would. This is a real
increase in the number of things that can break, and it is accepted because the
alternative is a boundary that has already been demonstrated to fail without
anyone noticing for a fortnight.

**Until phase 6, two ingestion paths are live at once.** Raw Loki keeps its
publication while shippers migrate, because migrating six shippers atomically
is not possible and a cutover that requires it would never be attempted. For
the duration, the estate has both the new authenticated path and the old
allowlisted one, and the security posture is the weaker of the two. That
interval is the cost of a safe migration; phase 6 exists to close it, and a
cutover that stalls before phase 6 has not delivered this decision — it has
only added a component.

**This repository now depends on another repository's release cadence.** A
change to the exposure contract is a Foundation change, reviewed and released
there, adopted here by moving a pin. That is slower than editing a local
schema, and it is the price of the facility being shared. It also means rule
19 cannot be marked enforced on this repository's own schedule.

**A reviewer must now hold two facts about every surface.** The exposure and
the family are separate decisions and both have to be read. That is more
review, deliberately: the failure this ADR answers is one nobody had to read
anything to cause.

## Alternatives considered

**Define the exposure contract in this repository.** Rejected, and it is the
alternative this ADR most nearly took. Nothing in the vocabulary is
observability-specific, and a local definition would produce a second
implementation of a facility whose whole purpose is to be the first. The fleet
would then hold two answers to "what is published, and to which families",
diverging on the first fix that only one of them received. The Foundation is
where reusable rendering, conformance and promotion mechanics already live
(`docs/ARCHITECTURE.md` §"Ownership"); putting this anywhere else would
contradict a boundary this repository has already accepted.

**Keep the IPv4 `DOCKER-USER` allowlist as the boundary, and repair the IPv6
half.** Rejected as an architecture, adopted only as containment. The three
reasons are given in full above and none of them is about IPv6: an address
allowlist authenticates a position rather than a sender, cannot revoke one
shipper without disturbing whoever shares its egress address, and breaks when a
NAT egress address moves — which this fleet has observed, not merely feared.
Repairing the IPv6 half would produce a correct version of the wrong boundary.

**`INPUT` filtering.** Rejected for now, on availability rather than on merit.
It is the technically correct place for a rule against a locally-terminated
connection, and §9.1 says so. It is also blocked: an `INPUT` rule carries SSH,
out-of-band recovery on this host is present but unproven, and no working root
password was confirmed. A change that can lock the estate out of its
observability host, with no demonstrated way back in, is not a change to make
because it is elegant. It remains the right second line, and this decision is
sequenced so that it can be added later without being depended on now.

**Unpublish Loki and have the shippers push somewhere else entirely.**
Rejected. It relocates the problem rather than solving it: whatever the six
shippers push to is then the thing that is externally reachable, and it needs
exactly the authentication, transport security, per-sender revocation and
declared exposure this decision specifies. The choice would be a new ingestion
system rather than a new boundary, with a data migration attached, and the
boundary work would still be outstanding afterwards. It also discards a
correctly-functioning Loki over a publication defect.

**Per-service TLS terminated in each container, rather than a shared ingress.**
Rejected. It multiplies the thing that has to be right by the number of
services: each container acquires its own certificate lifecycle, its own
credential store, its own authentication implementation and its own
configuration surface, and every one of those is a place where a service can be
correct while another is not. The census already shows what happens to a
posture maintained per-service by hand — nine rule blocks, one of which was
inert, and no single place to look. A shared ingress is one component to get
right, one credential store to rotate, one place where the refusal behaviour is
tested, and one listener set for conformance to compare against a declaration.
It is also the only shape in which the build-once criterion above can hold. The
cost is a single point of failure for external reachability, which is the trade
named under "The honest cost" and is accepted for it.
