#!/bin/bash

if [[ -z $NAME ]]; then
    serai-coordinator
else
    serai-coordinator --name $NAME
fi
