#!/bin/bash

if [[ -z $NAME ]]; then
    serai-processor
else
    serai-processor --name $NAME --coin $CHAIN
fi
