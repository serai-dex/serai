# Getting Started

### System Dependencies

##### Ubuntu

```
sudo apt-get install -y build-essential cmake clang-11 git curl python3-pip protobuf-compiler
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
rustup toolchain install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```

### Install Solidity

```
sudo pip3 install solc-select
solc-select install 0.8.16
solc-select use 0.8.16
```

### Install foundry and anvil (for tests)

```
cargo install --git https://github.com/foundry-rs/foundry --profile local --locked foundry-cli anvil
```

### Clone and Build Serai

```
git clone https://github.com/serai-dex/serai
cd serai
cargo build --release
```

### Run Tests

Running tests requires a Monero regtest node running in the background.

```
cargo test --all-features
```

### Run Serai in Development Mode

```
./target/release/serai-node --dev
```
