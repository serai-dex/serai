# Clone Serai

```
git clone https://github.com/serai-dex/serai.git
```

# Build and Run Serai

- Ubuntu LTS or WSL2 w/ Docker (Other distributions may also work or docker can be used)
    - Windows Guide: [https://dev.to/davidkou/running-docker-in-windows-subsystem-for-linux-wsl2-1k43](https://dev.to/davidkou/running-docker-in-windows-subsystem-for-linux-wsl2-1k43)
    - [https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)
- Setup Rust & Dependencies (Assuming Linux or WSL2)
  - Install Rust  `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
  
## Install Solidity Compiler
```
     sudo pip3 install solc-select
     solc-select install 0.8.16
     solc-select use 0.8.16
```
## Install Other Dependencies
```sudo apt-get install -y \
    cmake \
    libboost-all-dev \
    pkg-config \
    libssl-dev
```

## Build
```
    cd serai
    cargo build --release
```

## Run
```
./target/release/serai-node --chain dev
```

## Help
```
./target/release/serai-node --help
```