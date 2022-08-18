# Getting Started

## Clone Serai
```
    git clone https://github.com/serai-dex/serai.git
```

## Build and Run Serai

### Install Rust

#### Linux
```
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### Windows

Use WSL2 and Linux instructions.


#### Mac

```
    brew install rustup
```

### Install Solidity Compiler
```
    sudo pip3 install solc-select
    solc-select install 0.8.16
    solc-select use 0.8.16
```
### Install Other Dependencies
```
    sudo apt-get install -y \
    cmake \
    libboost-all-dev \
    pkg-config \
    libssl-dev
```

### Build
```
    cd serai
    cargo build --release
```

### Run
```
    ./target/release/serai-node --chain dev
    OR
    ./target/release/serai-node --dev
```

### Help
```
    ./target/release/serai-node --help
```