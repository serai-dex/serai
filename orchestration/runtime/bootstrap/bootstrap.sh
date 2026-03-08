#!/bin/sh

set -eux

WORKSPACE=$(cargo locate-project --workspace --message-format plain | sed s/"[^/]*$"//)

cd "$WORKSPACE"
cd orchestration/runtime/bootstrap

if [ -d "./stagex" ]; then
  rm -rf ./stagex
fi
git clone https://codeberg.org/kayabaNerve/stagex
cd stagex
git checkout 1e958b93b553145df5e20b04b705c297fa84b90a
make NOCACHE=1 pallet-rust

cd "$WORKSPACE"

docker buildx build --no-cache \
  --file ./orchestration/runtime/bootstrap/Containerfile \
  --build-context stagex/pallet-rust=oci-layout://./orchestration/runtime/bootstrap/stagex/out/pallet-rust \
  .
