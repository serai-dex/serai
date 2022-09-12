#!/bin/sh
geth --dev --dev.period 5 --verbosity 2 --networkid 15 --datadir "data" -mine --miner.threads 1 -http --http.addr 0.0.0.0 --http.port 8545 --allow-insecure-unlock --http.api "eth,net,web3,miner,personal,txpool,debug" --http.corsdomain "*" -nodiscover --http.vhosts="*"
