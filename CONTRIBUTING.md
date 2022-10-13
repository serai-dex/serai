# Contributing

Contributions come in a variety of forms. Developing Serai, helping document it,
using its libraries in another project, using and testing it, and simply sharing
it are all valuable ways of contributing.

This document will specifically focus on contributions to this repository in the
form of code and documentation.

### Rules

- Stable native Rust, nightly wasm and tools.
- `cargo fmt` must be used.
- `cargo clippy` must pass, except for the ignored rules (`type_complexity` and
`dead_code`).
- The CI must pass.

- Only use uppercase variable names when relevant to cryptography.

- Use a two-space ident when possible.
- Put a space after comment markers.
- Don't use multiple newlines between sections of code.
- Have a newline before EOF.

### Guidelines

- Sort inputs as core, std, third party, and then Serai.
- Comment code reasonably.
- Include tests for new features.
- Sign commits.

### Submission

All submissions should be through GitHub. Contributions to a crate will be
licensed according to the crate's existing license, with the crate's copyright
holders (distinct from authors) having the right to re-license the crate via a
unanimous decision.
