# Fleet Alloy agent

One native Grafana Alloy service per Linux VM collects host metrics, journald
and loopback-only OTLP. Docker hosts may additionally collect container metrics
and Docker logs. It exports all three signals over mutually authenticated TLS.
The agent UI remains on Alloy's loopback default; no exporter, log receiver or
OTLP listener is published.

`config-host.alloy` is the default profile and requires no container runtime.
`config.alloy` is the Docker profile. Installing that profile is refused unless
Docker is active, the socket is readable by Alloy, and no existing Promtail,
Alloy, Vector, Fluent Bit or application-direct writer owns the same streams.

The same configuration runs everywhere. Resolved backend URLs, the stable
logical `host_id`, and the server identity are private runtime material in
`/etc/default/dotmac-alloy`. Client certificates live under
`/etc/alloy/secrets/`. Neither belongs in this public repository.

## Required gates

1. Contabo API membership and assigned IPv6 are captured into private fleet
   inventory. Provider display names are descriptive only, never identity.
2. The host's global address and `/64` match that inventory; an IPv6 default
   route and independent HTTPS and DNS egress probes pass.
3. The host-only or Docker profile is selected from observed host state and
   installed as `/etc/alloy/config.alloy`; `alloy validate` passes before
   reload.
4. The service runs as the package-created `alloy` user. Config is
   `root:alloy 0640`; its directory is `0750`; state is `alloy:alloy 0750`.
5. `/metrics`, the UI, and both OTLP receivers are reachable only on loopback.
6. Central Prometheus shows fresh host, container and Alloy self-metrics with
   the expected `fleet`, `environment` and `host_id` labels.
7. Loki shows one injected journald canary and one Docker canary exactly once.
8. Tempo shows one injected span carrying the canary service and host resource
   identity.
9. An independent IPv6 vantage reaches the host's declared positive-control
   surface and cannot reach every loopback/none surface.
10. Restart and reboot preserve the agent, IPv6 route and both-family exposure
    verdicts; stopping Alloy triggers the missing-agent alert.

Container discovery requires Docker-socket access. Membership in `docker` is
root-equivalent, so the service configuration and runtime environment remain
root-owned, Alloy has no remote configuration source, and the systemd unit
uses `NoNewPrivileges` plus a read-only system view. A host without Docker uses
`config-host.alloy`; it is never added to the `docker` group.

Promtail is not installed by this path. A host already shipping a workload
directly must retire or exclude that path before Docker collection is enabled;
two writers for the same log stream are a rollout refusal.
