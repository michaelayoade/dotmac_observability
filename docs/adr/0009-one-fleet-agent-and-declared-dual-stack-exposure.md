# ADR-0009: One fleet agent and declared dual-stack exposure

- **Status:** Accepted
- **Date:** 2026-09-01
- **Supersedes:** ad-hoc host collectors and undeclared listener policy
- **Related:** ADR-0005, ADR-0008; `fleet/alloy/README.md`; Deployment
  Foundation `IngressPolicy.v1`

## Context

The provider inventory and a read-only guest census answer different
questions. Contabo reports which instances are running and which IPv6 prefix it
assigned. Only the guest can prove that the address is active, a default route
exists, egress works, a collector is not duplicating another writer, and the
listeners opened by the workload match its intended exposure.

The first complete census found all of these states in one fleet: Promtail and
standalone exporters beside hosts with no collector, Docker and host-only
systems, default-accept and default-drop input policies, and listeners whose
IPv4 and IPv6 sets differed. The differences are not repaired by one universal
port list. The fleet contains web, mail, DNS, VPN, database, object-storage,
RADIUS and orchestration roles, and a blanket allowlist would both break real
services and preserve accidental ones.

## Decision

### One telemetry writer

Grafana Alloy is the one fleet agent. Every Linux VM receives exactly one of
two profiles:

- `host`: host metrics, journald and loopback-only OTLP; no Docker group, socket
  or filesystem access.
- `docker`: everything in `host`, plus cAdvisor metrics and Docker logs; its
  Docker group and data-path access are an explicit profile add-on.

Promtail, a second Alloy, Vector, Fluent Bit or application-direct shipping for
the same stream is a cutover refusal. A legacy writer is retired only after the
replacement stream is fresh centrally and a uniquely labelled canary is found
exactly once. Standalone exporters may remain temporarily only when their
series are excluded from Alloy and their retirement is named in the rollout.

### Declared exposure, not inferred parity

The final ingress policy is default-deny for IPv4 and IPv6 on the packet path
each surface actually traverses, including host input and container forwarding.
Every reachable surface declares its protocol, exposure, address family,
authentication and named source policy. The observed sockets must equal that
declaration on IPv4 and IPv6. “Parity” does not mean every service must be
dual-stack: it means a family difference exists only because the owning
declaration says so.

Deployment Foundation owns binding, firewall rendering, transactional
application, rollback and external positive/negative proof through
`IngressPolicy.v1`. This repository owns the fleet telemetry profile and the
observability acceptance evidence. Workload owners decide which of their
surfaces should exist; neither this repository nor a firewall probe may invent
that business decision.

### Provider state is observation, not lifecycle authority

An unfamiliar instance that the API calls `running` is investigated, not
cancelled. Provider display names are hints. Cancellation or deletion requires
an explicit lifecycle decision naming the instance after its workload and data
ownership have been established.

## Rollout and cutover

Each host advances independently through the same gates:

1. Reconcile provider membership and canonical IPv6 with guest state.
2. Record the workload-owned surface declarations and the private address and
   source-set bindings.
3. Prove IPv6 route and egress and capture both-family external baselines from
   a vantage with a positive control.
4. Select the host or Docker Alloy profile and refuse competing writers.
5. Activate Alloy, prove fresh metrics, logs and OTLP centrally, then retire
   the old writer without overlap.
6. Apply the Foundation exposure plan transactionally. A failed positive
   control or an unexpected open port rolls back the change.
7. Reboot and repeat central freshness, both-family exposure and missing-agent
   alert tests before accepting the host.

The DNS, mail, database and orchestration roles are high-risk cohorts and do
not serve as first canaries. An address assigned by the API but absent or
unusable in the guest is repaired only under explicit mutation authorization
for that named host.

## Current enforcement boundary

The Alloy profiles and their privilege split are guarded by
`tests/architecture/test_fleet_alloy.py`. Live firewall application and socket
proof remain Deployment Foundation work; this decision does not describe the
currently observed fleet as repaired. Until each named host has an accepted
receipt, its census result is an observation and its standardization status is
pending.
