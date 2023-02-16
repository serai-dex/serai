#!/bin/sh

geth --dev --networkid 5208 --datadir "data" \
  -http --http.addr 0.0.0.0 --http.port 8545 \
  --http.api "web3,net,eth,miner" --http.corsdomain "*" --http.vhosts="*"
