#!/bin/sh
set -e

RUST_LOG=info lighthouse bn --execution-endpoint http://localhost:8551 --execution-jwt /home/ethereum/.jwt
