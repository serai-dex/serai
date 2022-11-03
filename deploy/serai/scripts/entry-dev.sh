#!/bin/bash

if [[ -z $VALIDATOR ]]; then
<<<<<<< HEAD
<<<<<<< HEAD
  serai-node --tmp --chain $CHAIN --name $NAME
else
  serai-node --tmp --chain $CHAIN --$NAME
=======
    serai-node --chain $CHAIN --$NAME
else
    serai-node --chain $CHAIN --$NAME --validator
>>>>>>> e3fc3f28 (Configure node for a multi-node testnet)
=======
    serai-node --chain $CHAIN --name $NAME
else
    serai-node --chain $CHAIN --$NAME
>>>>>>> 131355b1 (Correct Dave, Eve, and Ferdie to not run as validators)
fi
