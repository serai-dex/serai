#!/bin/sh
set -e

serai-node --base-path /volume --unsafe-rpc-external --rpc-cors all --chain testnet --validator
