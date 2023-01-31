#!/bin/sh
# Setup Environment
RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"
BLOCK_TIME=${BLOCK_TIME:=5}

# Run Monero
# TODO: Restore Auth
monerod --regtest --rpc-access-control-origins * --confirm-external-bind \
  --rpc-bind-ip=0.0.0.0 --offline --fixed-difficulty=1 \
  --non-interactive --mining-threads 1 --detach
