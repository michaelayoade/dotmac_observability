# deploy/

What is applied to a host, and how.

`deploy/rendered/` holds the output of `dotmac-observability render`: exactly
three files, in the shape `render.render_control_plane` produces them.

```
prometheus/prometheus.yml
alertmanager/alertmanager.yml
docker-compose.yml
```

These bytes are **generated and committed, and never hand-edited.** Committing
them is what makes a routing change reviewable as a diff of the actual
Alertmanager configuration rather than of the TOML that implies it, and what
lets an operator with a checkout and no network hold working configuration.
`make render` regenerates them; `make render-check` re-renders and compares
BYTES, reporting `missing`, `differs` and `unexpected` paths. Every rendered
file carries a three-line generated-by header saying so.

**The directory is empty today.** PR 1 ships no production inventory, so there
is nothing to render from. The equivalent committed output for the reference
fixture lives at `tests/fixtures/reference/rendered/` and is what the
determinism gate compares against in the meantime. `deploy/rendered/` fills in
PR 3, and `render-check` and `schema-check` join `make check` at the same time.

**Trap:** editing a file here to fix production is the exact gesture this
repository was created to remove. The edit is silently reverted by the next
`make render`, and in the interval it is a byte on a host that no reviewed input
produced. Change the inventory and re-render. See ADR-0002.
