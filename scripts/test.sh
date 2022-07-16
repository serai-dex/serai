#!/bin/bash
./coins/monero/c/monero/build/release/bin/monerod --detach --regtest --offline --fixed-difficulty=1 --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081
cargo test