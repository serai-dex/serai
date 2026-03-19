# Contributing

Contributions may come in a variety of forms. While Serai welcomes developers,
Serai also welcomes people who wish to help document it, users who wish to
consume our libraries, people who wish to test Serai and give feedback, and
people who share Serai via word of mouth. All can be valuable ways to
contribute.

All places to contribute, and spaces in general, are governed by our
[Code of Conduct](/Code of Conduct.md).

This document will specifically focus on contributions to this repository and
the files present here however, in the form of writing code. For contributions
to this repository regarding documentation, we don't currently have specific
guidelines other than the sections of this document which remain relevant.

### Dependencies

Serai primarily requires Rust, presumably via [`rustup`](https://rustup.rs),
to build its libraries. The [`rust-toolchain.toml`](/rust-toolchain.toml) in
the root of the workspace is sufficient to install the necessary targets and
components. Please note the `nightly` channel is used for `cargo fmt`
(`cargo +nightly fmt`).

Some system packages _may_ be required, such as `git`, `curl`,
`ca-certificates`, `libclang-dev`, and most notably `protobuf-compiler`. While
`rocksdb` is not required as a package, building `rocksdb` can take a notable
amount of time which is entirely avoidable if a sufficiently modern version is
available via your system and the `ROCKSDB_LIB_DIR` environment variable is set
(optionally along with the `SNAPPY_LIB_DIR` environment variable).

Building the Ethereum smart contracts (and libraries for them) relies on an
exact version of Solidity, currently `0.8.29`. Our recommended way to install
Solidity is via [`svm-rs`](https://docs.rs/svm-rs) as follows:

```sh
cargo install svm-rs
svm install 0.8.29
svm use 0.8.29
```

Building the Serai node can be done locally for development purposes. Building
the Serai node for non-development environments requires using an OCI-based
build system. While this will likely be [Docker](https://docker.com), and the
relevant components may be referred to simply as 'Docker', we do not
intentionally require Docker. Compatibility issues with other OCI tooling
should be [submitted via GitHub](https://github.com/serai-dex/serai/issues).
Serai is currently partially tested with [`podman`](https://podman.io) (aliased
to `docker`) and a long-term goal is to fully test Serai with both `docker` and
`podman` (https://github.com/serai-dex/serai/issues/709).
`docker buildx build` is used by some tests which _require_ being built with
[BuildKit](https://github.com/moby/buildkit).

When building binaries, or running tests, via OCI containers, the user is
expected to able to spawn/manage containers (as potentially obvious). This
implies the setup should be rootless
([as possible with Docker](https://docs.docker.com/engine/security/rootless/)
and as inherent to `podman`'s architecture).

### Test Dependencies

The Serai services premise their tests on OCI containers. To produce their
definitions, the following commands are necessary:

```
cargo run -p serai-orchestrator -- key_gen dev
cargo run -p serai-orchestrator -- setup dev
```

[`networks/bitcoin`](
  https://github.com/serai-dex/serai/tree/develop/networks/bitcoin
) assumes a Bitcoin node running in the background with the
configuration demonstrated in our
[GitHub Actions](
  https://github.com/serai-dex/serai/tree/develop/.github/actions/bitcoin/action.yml
). One may be spawned as an OCI container via
`cargo run -p serai-orchestrator -- start dev bitcoin-daemon`.

[`networks/ethereum`](
  https://github.com/serai-dex/serai/tree/develop/networks/ethereum
) uses [`alloy-node-bindings`](https://docs.rs/alloy-node-bindings) to spawn
instances of
[Anvil](https://github.com/foundry-rs/foundry/tree/master/crates/anvil), which
requires `anvil` be present in the user's path. This can be installed along
with [Foundry](https://github.com/foundry-rs/foundry) as follows:


```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Contributing Commits

Commits should be submitted via a pull request to our
[GitHub repository](https://github.com/serai-dex/serai). Exceptionally, patch
files may be emailed to
[`patches@serai.exchange`](mailto:patches@serai.exchange).

Commits will be checked against our Continuous Integration, orchestrated via
GitHub Actions and ran by GitHub's provided runners for public repositories.
These will perform a myriad of static analyses and ran applicable tests. These
SHOULD be run locally _before_ making a pull request. As a rule of thumb,

```sh
cargo +nightly fmt
cargo clippy --all-features --all-targets
```

should not yield any warnings nor errors due to your changes.

All contributions _MUST_ follow the terms within our
[licensing policies](/LICENSE.md).

### Discussing Development

Serai organizes via [Discord](https://discord.gg/mpEUtJR3vz) and
[Matrix](https://matrix.to/#/#serai:matrix.org) (the two being bridged to each
other). If you have any questions or comments, or need help, please join and
ask. We welcome people to learn more about the project and contribute.
