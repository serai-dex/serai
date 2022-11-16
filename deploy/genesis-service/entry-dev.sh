#!/bin/sh
date +%s > /genesis
genesis=`cat /genesis`
echo "Genesis : $genesis"

tail -f /dev/null
