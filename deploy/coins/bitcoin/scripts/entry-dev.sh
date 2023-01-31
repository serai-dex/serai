#!/bin/sh

RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

bitcoind -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcallowip=0.0.0.0/0 -rpcbind=127.0.0.1 -rpcbind=$(hostname)
