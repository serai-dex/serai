#check=skip=FromPlatformFlagConstDisallowed
# We want to explicitly set the platform to ensure a constant host environment

# rust:1.91.1-alpine as of November 11th, 2025 (GMT)
FROM --platform=linux/amd64 rust@sha256:700c0959b23445f69c82676b72caa97ca4359decd075dca55b13339df27dc4d3

# In order to compile the runtime, including the `proc-macro`s and build scripts, we need the
# required development libraries. These are traditionally provided by `musl-dev` which is not
# inherently included with this image (https://github.com/rust-lang/docker-rust/issues/68). While we
# could install it here, we'd be unable to pin the installed package by its hash as desired.
#
# Rust does have self-contained libraries, intended to be used when the desired development files
# are not otherwise available. These can be enabled with `link-self-contained=yes`. Unfortunately,
# this doesn't work here (https://github.com/rust-lang/rust/issues/149371).
#
# While we can't set `link-self-contained=yes`, we can install Rust's self-contained libraries onto
# our system so they're generally available.
RUN echo '#!/bin/sh' > libs.sh
RUN echo 'set -e' >> libs.sh
RUN echo 'SYSROOT=$(rustc --print sysroot)' >> libs.sh
RUN echo 'LIBS=$SYSROOT/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained' >> libs.sh
RUN echo 'ln -s $LIBS/Scrt1.o $LIBS/crti.o $LIBS/crtn.o /usr/lib' >> libs.sh
# We also need `libc.so` which is already present on the system, just not under that name
RUN echo 'ln -s /lib/libc.musl-x86_64.so.1 /usr/lib/libc.so' >> libs.sh
RUN /bin/sh ./libs.sh

# Add the WASM toolchain
RUN rustup target add wasm32v1-none

# Add files for build
ADD patches /serai/patches
ADD common /serai/common
ADD crypto /serai/crypto
ADD networks /serai/networks
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD substrate /serai/substrate
ADD orchestration/Cargo.toml /serai/orchestration/Cargo.toml
ADD orchestration/src /serai/orchestration/src
ADD mini /serai/mini
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Build the runtime
RUN cargo build --release -p serai-runtime

# Copy the runtime to the provided volume
CMD ["cp", "/serai/target/release/wbuild/serai-runtime/serai_runtime.wasm", "/volume/serai.wasm"]
