#!/bin/bash

export GENESIS=$(cat /temp/genesis)
if [[ -z $VALIDATOR ]]; then
  serai-node --tmp --chain $CHAIN --name $NAME
else
  serai-node --tmp --chain $CHAIN --$NAME
fi
