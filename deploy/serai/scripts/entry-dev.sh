#!/bin/bash

export GENESIS=$(cat /temp/genesis)
# TODO: Correct RPC listening
if [[ -z $VALIDATOR ]]; then
  serai-node --tmp --chain $CHAIN --name $NAME --unsafe-rpc-external --unsafe-ws-external --rpc-cors=all
else
  serai-node --tmp --chain $CHAIN --$NAME --rpc-external --ws-external --rpc-cors=all
fi
