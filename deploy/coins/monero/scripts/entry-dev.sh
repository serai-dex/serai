#!/bin/sh
# Setup Environment
RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"
BLOCK_TIME=${BLOCK_TIME:=5}

# Run Monero
monerod --regtest --rpc-login ${RPC_USER}:${RPC_PASS} \
--rpc-access-control-origins * --confirm-external-bind \
--rpc-bind-ip=0.0.0.0 --offline --fixed-difficulty=1 \
--non-interactive --mining-threads 1 --bg-mining-enable --detach

# give time to monerod to start
while true; do
    sleep 5
done

# Create wallet from PRIV_KEY in monero wallet
