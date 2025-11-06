# Getting Started

### Dependencies

##### Ubuntu

```
sudo apt-get install -y build-essential clang-11 pkg-config cmake git curl protobuf-compiler
```

### Install rustup

##### Linux

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

##### macOS

```
brew install rustup
```

### Install Rust

```
rustup update
rustup toolchain install stable
rustup target add wasm32v1-none
rustup toolchain install nightly
rustup target add wasm32v1-none --toolchain nightly
```

### Install Solidity with `svm`

```
cargo install svm-rs
svm install 0.8.29
svm use 0.8.29
```

### Install foundry (for tests)

```
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Clone and Build Serai

```
git clone https://github.com/serai-dex/serai
cd serai
cargo build --release --all-features
```

### Run Tests

Running tests requires:

- [A rootless Docker setup](https://docs.docker.com/engine/security/rootless/)
- A properly configured Bitcoin regtest node (available via Docker)
- A properly configured Monero regtest node (available via Docker)
- A properly configured monero-wallet-rpc instance (available via Docker)

To start the required daemons, one may run:

```
cargo run -p serai-orchestrator -- key_gen dev
cargo run -p serai-orchestrator -- setup dev
```

and then:

```
cargo run -p serai-orchestrator -- start dev bitcoin-daemon monero-daemon monero-wallet-rpc
```

Finally, to run the tests:

```
cargo test --all-features
```
