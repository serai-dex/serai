#!/bin/sh

monero-wallet-rpc \
  --allow-mismatched-daemon-version \
  --daemon-address monero:18081 --daemon-login serai:seraidex \
  --disable-rpc-login --rpc-bind-ip=0.0.0.0 --rpc-bind-port 18082 --confirm-external-bind \
  --wallet-dir /home/monero
