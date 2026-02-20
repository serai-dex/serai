#!/bin/sh

set -eux

WORKSPACE=$(cargo locate-project --workspace --message-format plain | sed s/"[^/]*$"//)

cd "$WORKSPACE"
cd orchestration/runtime/bootstrap

if [ -d "./stagex" ]; then
  rm -rf ./stagex
fi
git clone https://codeberg.org/stagex/stagex
cd stagex
git checkout a49d2c4ab767e599d7d9e0a66c9b14c52024da6b
make NOCACHE=1 pallet-rust

cd "$WORKSPACE"

docker buildx build --no-cache \
  --file ./orchestration/runtime/bootstrap/Containerfile \
  --build-context stagex/pallet-rust=oci-layout://./orchestration/runtime/bootstrap/stagex/out/pallet-rust \
  .
