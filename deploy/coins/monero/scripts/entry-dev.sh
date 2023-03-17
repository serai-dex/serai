#!/bin/sh

RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

# Run Monero
# TODO: Restore Auth
monerod --regtest --offline --fixed-difficulty=1 \
  --rpc-bind-ip=0.0.0.0 --rpc-access-control-origins * --confirm-external-bind
