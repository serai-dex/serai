#!/bin/bash

export GENESIS=$(cat /temp/genesis)
if [[ -z $VALIDATOR ]]; then
  serai-node --tmp --chain $CHAIN --name $NAME --unsafe-rpc-external --ws-external --rpc-cors=all
else
  serai-node --tmp --chain $CHAIN --$NAME --unsafe-rpc-external --ws-external --rpc-cors=all
fi
