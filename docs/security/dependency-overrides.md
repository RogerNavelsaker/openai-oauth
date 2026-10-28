# Dependency overrides

- `deepmerge@4.1.2` overrides the `addons-linter` transitive `4.3.1` pin to avoid the prototype-poisoning advisory affecting `4.2.0`–`4.3.1`. The override is exercised by the Firefox add-on lint check; remove it when `addons-linter` adopts a patched release.
