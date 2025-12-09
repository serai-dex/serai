#!/bin/sh
set -e

${SERAI_NAME:?} # Ensure this is present in the environment
serai-node --unsafe-rpc-external --rpc-cors all --chain local --"$SERAI_NAME"
