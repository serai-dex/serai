# Getting Started

### Dependencies

##### Ubuntu

```
sudo apt-get install -y build-essential cmake clang-11 git curl python3-pip protobuf-compiler libssl-dev pkg-config
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
sudo pip3 install solc-select
solc-select install 0.8.16
solc-select use 0.8.16
```

### Install Solidity Compiler Version Manager

```
cargo install svm-rs
svm install 0.8.16
svm use 0.8.16
```

### Install foundry and anvil (for tests)

```
cargo install --git https://github.com/foundry-rs/foundry --profile local --locked foundry-cli anvil
```

### Clone and Build Serai

```
git clone https://github.com/serai-dex/serai
cd serai
cargo build --release --all-features
```

### Run Tests

Running tests requires:

- A properly configured Bitcoin regtest node (available via Docker)
- A properly configured Monero regtest node (available via Docker)
- A properly configured monero-wallet-rpc instance
- A debug Serai node (`cd substrate/node && cargo build`)

```
cargo test --all-features
```

### Run Serai in Development Mode

```
./target/release/serai-node --dev
```

### Run Serai with Orchestration

Under `/orchestration`, you can find our orchestration components for running
the entire infrastructure of Serai in a local environment using Docker Compose
or Kubernetes.

[Run Serai with Docker Compose](../orchestration/README.md)

[Run Serai with Kubernetes](../orchestration/kubernetes/README.md)
