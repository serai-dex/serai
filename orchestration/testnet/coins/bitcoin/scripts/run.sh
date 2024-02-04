#!/bin/bash

RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

bitcoind -txindex -testnet -port=8333 \
  -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS \
  -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 -rpcport=8332
