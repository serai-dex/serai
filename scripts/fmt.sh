#!/bin/bash
rustup component add rustfmt --toolchain nightly-x86_64-unknown-linux-gnu
cargo +nightly fmt --all