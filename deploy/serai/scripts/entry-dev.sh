#!/bin/bash

if [[ -z $VALIDATOR ]]; then
  serai-node --tmp --chain $CHAIN --name $NAME
else
  serai-node --tmp --chain $CHAIN --$NAME
fi
