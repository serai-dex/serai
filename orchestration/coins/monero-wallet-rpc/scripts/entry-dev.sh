#!/bin/sh

monero-wallet-rpc \
  --disable-rpc-login \
  --rpc-bind-ip=0.0.0.0 --confirm-external-bind \
  --daemon-address monero:18081 --allow-mismatched-daemon-version \
  --wallet-dir /home/monero
