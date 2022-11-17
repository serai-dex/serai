#!/bin/sh
date +%s > /temp/genesis
genesis=`cat /temp/genesis`
echo "Genesis : $genesis"

tail -f /dev/null
