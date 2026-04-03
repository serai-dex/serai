# `cargo vet` Statements for Serai's Supply Chain

This folder contains the `cargo vet` statements for Serai's supply chain, an
active [work in progress](https://github.com/serai-dex/serai/issues/315) for
Serai.

The primary goal for Serai to reduce its supply-chain risk is via minimizing
the supply chain itself. While high-quality dependencies are better than
low-quality in-house replacements, dependencies should not be eagerly reached
for. For more information on this goal specifically, please see
[`patches/`](/patches).

For the rest of our supply chain, we are working towards comprehensive vetting
statements.

### Installation

At this time, Serai makes use of a fork of `cargo-vet` with support for declaring
non-`crates.io` dependencies as third party and therefore requiring vet
statements. This is due to Serai's non-trivial use of `git` dependencies. For
context, please see https://github.com/mozilla/cargo-vet/issues/683.

```
cargo install --locked cargo-vet --git https://github.com/kayabaNerve/cargo-vet --rev d2fb27daaeb839e5fa4f6b28c5cdd4a9185542b5
```

### Policies

- `audits-as-crates-io` must only be explicitly set to `false` for crates
  within this repository.
- `safe-to-run`, `safe-to-deploy` mean the code has been reviewed to not be
  actively malicious and to not contain any binary artifacts. It does not mean
  they have been professionally audited nor reviewed to lack bugs/security
  issues.
- `reviewed` means the code has been reviewed for security issues and the
  associated bugs, and found in generally good standing, even if not free of
  problems/concerns.
- `audited` means the code has been professionally reviewed for security issues
  and bugs at some point during its life. It is used for metadata and is not
  actively explicitly required for any dependencies.
