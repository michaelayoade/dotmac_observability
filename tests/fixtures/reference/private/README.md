# The synthetic private inventory

A tracked instance of `contracts/private-inventory.schema.json` — the document
type ADR-0004 says never enters public Git. That is not a contradiction and it
is not an exception: it is the corpus the resolution layer is tested against,
and it is safe for reasons a test can check rather than reasons a reader has to
take on trust.

Two properties, both asserted by
`tests/architecture/test_public_inventory_carries_no_private_material.py`:

* **Every endpoint is under `.invalid`.** RFC 6761 reserves that TLD as
  permanently unresolvable, so these names cannot become real by accident or by
  somebody registering them.
* **Every store path is under `secret/fixture/`.** A reserved prefix that names
  no real OpenBao namespace. The private-material detector exempts that prefix
  *by pattern* rather than exempting this directory *by path*, which is the
  stronger arrangement: a real store path pasted into this very file is still
  caught, because the detector never learns that the file is trustworthy — only
  that one reserved prefix is not a disclosure.

The distinction worth keeping straight is between the file and the shape. What
must never be committed is a document that RESOLVES something — a real host, a
real port, a real credential custody path. A document that resolves nothing,
against names that cannot exist, discloses nothing while still exercising every
join, every mismatch gate and every byte of the render.

ADR-0004 was explicit that the fixture keeps its synthetic endpoints
permanently. They are not placeholders awaiting real values: under the split
there are no real values to put here, ever, and a future change that fills them
in has misread the decision.
