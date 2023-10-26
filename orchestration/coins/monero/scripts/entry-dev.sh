#!/bin/sh

RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

# Run Monero
# TODO: Restore Auth
monerod --non-interactive --regtest --offline --fixed-difficulty=1 \
  --no-zmq --rpc-bind-ip=0.0.0.0 --confirm-external-bind \
  --rpc-access-control-origins * --disable-rpc-ban
