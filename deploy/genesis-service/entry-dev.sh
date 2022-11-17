#!/bin/sh

date +%s > /temp/genesis
GENESIS=$(cat /temp/genesis)
echo "Genesis : $GENESIS"

tail -f /dev/null
