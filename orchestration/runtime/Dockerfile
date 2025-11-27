# rust:1.91.1-alpine as of November 11th, 2025 (GMT)
FROM --platform=linux/amd64 rust@sha256:700c0959b23445f69c82676b72caa97ca4359decd075dca55b13339df27dc4d3 AS deterministic

# Add the wasm toolchain
RUN rustup target add wasm32v1-none

FROM deterministic

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

# `proc-macro`s are difficult here on Alpine, with `musl`. Rust expects to be able to build the
# `proc-macro`s into dynamic libraries, which requires setting `target-feature=-crt-static`
# (disabling static linking). This will become the default at some point in the future
# (https://github.com/rust-lang/compiler-time/issues/422).
#
# While this is fine, Rust/musl will expect to be able to link `crti.o` into the built
# `proc-macro`s. `crti.o` would be provided by the `musl-dev` package which Rust's docker images do
# not include by default (https://github.com/rust-lang/docker-rust/issues/68). While we could add it
# ourselves, we cannot do so _while pinning by a hash_. We'd have to pin it by its version tag.
#
# Rust does provide `crti.o` as part of its self-contained builds. We cannot use
# `link-self-contained=yes` here however, as that would link `musl` into the `proc-macro`s and
# `musl` may only be linked once into a running program
# (https://github.com/rust-lang/rust/issues/149371).
#
# While we can't use self-contained builds, we can use the libraries shipped for self-contained
# builds. We do so here, adding Rust's libraries to the linker's search path, making `crti.o`
# available without adding `musl-dev`.
RUN echo 'SYSROOT=$(rustc --print sysroot)' >> libs.sh
RUN echo 'LIBS=$SYSROOT/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained' >> libs.sh
RUN echo 'ln -s $LIBS/Scrt1.o $LIBS/crti.o $LIBS/crtn.o /usr/lib' >> libs.sh
# For `libc`, we need a shared library, not a static archive, so we convert it now
RUN echo 'gcc -shared -o /usr/lib/libc.so -L$LIBS -Wl,--whole-archive -lc -Wl,--no-whole-archive -nodefaultlibs' >> libs.sh
RUN /bin/sh ./libs.sh

ENV RUSTFLAGS="-Ctarget-feature=-crt-static"
CMD cargo build --release -p serai-runtime && \
  mkdir -p /volume && \
  cp /serai/target/release/wbuild/serai-runtime/serai_runtime.wasm /volume/serai.wasm
