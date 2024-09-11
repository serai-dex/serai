#!/bin/sh

RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

bitcoind -regtest --port=8333 \
  -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS \
  -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 -rpcport=8332 \
  $@
