#!/bin/sh

monero-wallet-rpc --disable-rpc-login --rpc-bind-port 6061 --rpc-bind-ip=0.0.0.0 --confirm-external-bind --allow-mismatched-daemon-version --wallet-dir /home/monero
