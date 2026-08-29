# deploy/

What is applied to a host, and how.

`deploy/rendered/` holds the output of `dotmac-observability render`: exactly
three files, in the shape `render.render_control_plane` produces them.

```
prometheus/prometheus.yml
alertmanager/alertmanager.yml
docker-compose.yml
```

These bytes are **generated and never hand-edited.** `make render`
regenerates them; `make render-check` re-renders and compares BYTES, reporting
`missing`, `differs` and `unexpected` paths. Every rendered file carries a
three-line generated-by header saying so.

**This directory is empty in Git, and ADR-0006 makes that permanent.** It is
not waiting for PR 3 to fill it.

A production render needs the private inventory, and the bytes it produces
legitimately contain resolved endpoints and credential basenames — exactly the
material ADR-0004 keeps out of a public repository. So a production render is
produced at promotion time, hashed, and recorded in the receipt by digest. It
is never committed, and nobody without the private inventory can reproduce it.

The committed render lives at `tests/fixtures/reference/rendered/`, against the
synthetic fixture, and is what `make render-check` compares. That is exactly as
strong a determinism gate as one over production inputs would be: determinism
is a property of the renderer and its inputs, not of whether those inputs are
real. What is genuinely lost is reproducibility by a stranger, which ADR-0004
named and priced.

**Trap:** editing a file here to fix production is the exact gesture this
repository was created to remove. The edit is silently reverted by the next
`make render`, and in the interval it is a byte on a host that no reviewed input
produced. Change the inventory and re-render. See ADR-0002.
