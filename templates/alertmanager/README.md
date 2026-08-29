# templates/alertmanager/

Alertmanager notification templates (`*.tmpl`). These shape what a delivered
notification says; they decide nothing about whether it is delivered.

The rendered Alertmanager configuration always declares
`templates: ["/etc/alertmanager/templates/*.tmpl"]` as a glob over the release's
templates directory, so whatever a staged release contains here is loaded. That
path is a fixed constant in `render.py` (`_TEMPLATES_GLOB`), matching the
directory the compose file mounts, so the configuration and the mount cannot
disagree.

No schema governs this directory: Go text templates are not JSON documents. The
oracle is `amtool`, which the promotion receipt reserves a field for
(`validation.amtool_config`) and which CI's `config-validation` job runs
against the rendered Alertmanager configuration.

**Populated by PR 3**, alongside the routing this repository actually promotes.
Empty today, which is valid: the glob matches nothing and Alertmanager uses its
built-in defaults.

**Trap:** a template is the last place an alert's content can leak. Render label
and annotation values that products control; never interpolate anything from a
secrets file, a receiver credential or a URL that carries a key, and remember
that a template renders into a message that will be archived somewhere with
weaker access control than this repository.
