#!/bin/bash
if [[ -z $VALIDATOR ]]; then
    serai-node --chain $CHAIN --$NAME
else
    serai-node --chain $CHAIN --$NAME --validator
fi
