#!/bin/sh

geth --dev --networkid 5208 --datadir "eth-devnet" \
  --http --http.api "web3,net,eth,miner" \
  --http.addr 0.0.0.0 --http.port 8545 \
  --http.vhosts="*" --http.corsdomain "*"
