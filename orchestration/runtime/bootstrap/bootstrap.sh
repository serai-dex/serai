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
git checkout 75844e6ade2532734db5cbddddb6401df470059c
make NOCACHE=1 pallet-rust

cd "$WORKSPACE"

docker buildx build --no-cache \
  --file ./orchestration/runtime/bootstrap/Containerfile \
  --build-context stagex/pallet-rust=oci-layout://./orchestration/runtime/bootstrap/stagex/out/pallet-rust \
  .
