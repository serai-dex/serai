# Getting Started - Debain 12 fresh install
This guide attempts to outline the steps required to setup a validator from a clean Debian 12 installation DVD or Netinstall. This guide is accurate as of Debain 12.5.0. 

## Dependencies
Before you get started, you need a few basic tools.

Install Sudo
```
sudo apt-get install sudo
```
_update /etc/sudoers_

#### Install newuidmap / newgidmap and iptables to the fresh install
```
sudo apt-get install -y uidmap
sudo apt-get install -y iptables
```

#### Install Fuse overlaysfs
```
sudo apt-get install -y fuse-overlayfs
```

#### Install Fuse slirp4netns
Rootless docker requires version of slirp4netns greater than v0.4.0 (when vpnkit is not installed).
```
sudo apt-get install -y slirp4netns
```

### Install docker ROOTLESS 
https://docs.docker.com/engine/security/rootless/
This only works if you do not have docker installed. This guide assumes a fresh install of Debain 12.5. 

Run the rootless docker install script as the user you would like to run rootless with. I choose pid 1000 in this example. 

```
curl -fsSL https://get.docker.com/rootless | sh
```
[INFO] Make sure the following environment variables are set (or add them to ~/.bashrc and update TESTUSER to current username)
```
export PATH=/home/TESTUSER/bin:$PATH
export DOCKER_HOST=unix:///run/user/1000/docker.sock
```
The binaries will be installed at ~/bin.

#### Run a quick docker hello-world test
```
docker run hello-world
```
if you see you are good to go!:

```
Hello from Docker!
This message shows that your installation appears to be working correctly.....
```

## Install development tools
These tools are required to setup, download, compile and install Serai

#### install basic tools for admin

```
sudo apt-get install curl -y
```

### Install rustup

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
_Exit the current terminal to update enviroment variables and log back in._

### Install Rust

```
rustup update
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
rustup toolchain install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```
### Install local dev tooling packages
```
sudo apt install build-essential -y
sudo apt install protobuf-compiler -y
sudo apt install git -y
sudo apt install clang -y
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

## Build Serai

### Clone and Build Serai
```
git clone https://github.com/serai-dex/serai
cd serai
cargo build --release --all-features
```

## Run Tests

Running tests requires:

- [A rootless Docker setup](https://docs.docker.com/engine/security/rootless/)
- A properly configured Bitcoin regtest node (available via Docker)
- A properly configured Monero regtest node (available via Docker)
- A properly configured monero-wallet-rpc instance (available via Docker)

#### To test that you have these installed properly, run the following:

To start the required Dev daemons, one may run:

```
cargo run -p serai-orchestrator -- key_gen dev
cargo run -p serai-orchestrator -- setup dev
```

and then to deploy daemons into the dev docker network:

```
cargo run -p serai-orchestrator -- start dev bitcoin-daemon monero-daemon monero-wallet-rpc
```

Finally, to run the all the self tests:

```
cargo test --all-features
```
