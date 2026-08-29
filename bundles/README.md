# bundles/

The product alert bundles accepted for each environment, as digest-pinned
locks. Governed by `contracts/bundle-lock.schema.json`.

A lock entry names the `product`, the `environment`, the 40-character
`source_revision` on the product's protected `main`, the `image_digest` and
`product_manifest_digest`, the `rules_artifact` pointer with its `rules_sha256`
and `metrics_manifest_sha256`, the `rule_count`, and the owner and
`runbook_base` an alert's runbook link resolves against.

This repository pins and assembles; the product authors. Nothing here contains
an alert expression, and a fetched bundle is never edited locally
(`AGENTS.md` rule 5). If a rule is wrong, the product publishes a new bundle
and the pin moves.

**Populated by PR 3** (the lock documents and `bundle.py`, which fetches and
digest-verifies). **PR 8** onboards the first real product bundle, ERP.

**Trap:** a version string is not an identity. Promotion fetches the artifact
and refuses it unless every digest matches, so a lock that records a tag, an
abbreviated SHA or a "latest" pointer is not a pin, and a locally patched
bundle makes one version name two contracts and renders every receipt that
cites its digest unverifiable.
