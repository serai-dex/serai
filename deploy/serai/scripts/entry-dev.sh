#!/bin/bash

if [[ -z $VALIDATOR ]]; then
<<<<<<< HEAD
  serai-node --tmp --chain $CHAIN --name $NAME
else
  serai-node --tmp --chain $CHAIN --$NAME
=======
    serai-node --chain $CHAIN --$NAME
else
    serai-node --chain $CHAIN --$NAME --validator
>>>>>>> e3fc3f28 (Configure node for a multi-node testnet)
fi
