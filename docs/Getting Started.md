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
rustup target add wasm32-unknown-unknown
rustup toolchain install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```

### Install Solidity

```
cargo install svm-rs
svm install 0.8.16
svm use 0.8.16
```

### Install Solidity Compiler Version Manager

```
cargo install svm-rs
svm install 0.8.16
svm use 0.8.16
```

### Install foundry (for tests)

```
cargo install --git https://github.com/foundry-rs/foundry --profile local --locked forge cast chisel anvil
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

```
cargo test --all-features
```
