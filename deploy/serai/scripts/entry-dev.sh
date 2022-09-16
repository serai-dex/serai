#!/bin/bash
if [[ -z $VALIDATOR ]]; then
    serai-node --chain $CHAIN --name $NAME
else
    serai-node --chain $CHAIN --name $NAME --validator
fi
