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
git checkout e8b3a381c01126b04f6ef7ee62394197ec135a46 # 2026.03.0
make NOCACHE=1 core-busybox pallet-rust

cd "$WORKSPACE"

docker buildx build --no-cache \
  --file ./orchestration/runtime/bootstrap/Containerfile \
  --build-context stagex/core-busybox=oci-layout://./orchestration/runtime/bootstrap/stagex/out/core-busybox \
  --build-context stagex/pallet-rust=oci-layout://./orchestration/runtime/bootstrap/stagex/out/pallet-rust \
  .
