#!/bin/sh
set -e

RUST_LOG=info reth node --authrpc.jwtsecret /home/ethereum/.jwt
