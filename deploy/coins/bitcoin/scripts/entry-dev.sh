#!/bin/sh
RPC_USER="${RPC_USER:=serai}"
RPC_PASS="${RPC_PASS:=seraidex}"

# address: bcrt1q7kc7tm3a4qljpw4gg5w73cgya6g9nfydtessgs
# private key: cV9X6E3J9jq7R1XR8uPED2JqFxqcd6KrC8XWPy1GchZj7MA7G9Wx
MINER="${MINER:=bcrt1q7kc7tm3a4qljpw4gg5w73cgya6g9nfydtessgs}"
PRIV_KEY="${PRIV_KEY:=cV9X6E3J9jq7R1XR8uPED2JqFxqcd6KrC8XWPy1GchZj7MA7G9Wx}"
BLOCK_TIME=${BLOCK_TIME:=5}

bitcoind -regtest -txindex -fallbackfee=0.000001 -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS -rpcallowip=0.0.0.0/0 -rpcbind=127.0.0.1 -rpcbind=$(hostname) &

# give time to bitcoind to start
while true
do
	bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS generatetoaddress 100 $MINER && break
	sleep 5
done

bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS createwallet "miner" false false $RPC_PASS false false true &&
bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS walletpassphrase $RPC_PASS 60 &&
bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS importprivkey $PRIV_KEY

# mine a new block every BLOCK_TIME
while true
do
	bitcoin-cli -regtest -rpcuser=$RPC_USER -rpcpassword=$RPC_PASS generatetoaddress 1 $MINER
	sleep $BLOCK_TIME
done
