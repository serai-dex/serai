#check=skip=FromPlatformFlagConstDisallowed
# We want to explicitly set the platform to ensure a constant host environment

# rust:1.91.1-alpine as of December 4th, 2025 (GMT)
FROM --platform=linux/amd64 rust@sha256:84f263251b0ada72c1913d82a824d47be15a607f3faf015d8bdae48db544cdf2 AS builder

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
RUN cargo build --release -p serai-runtime --no-default-features

# Copy the artifact to its own image which solely exists to further export it
FROM scratch
# Copy `busybox`, including the necessary shared libraries, from the builder for a functioning `cp`
COPY --from=builder /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1 /lib/
COPY --from=builder /bin/busybox /bin/
ENV LD_LIBRARY_PATH=/lib/
ENV PATH=/bin
# Copy the artifact itself
COPY --from=builder /serai/target/release/wbuild/serai-runtime/serai_runtime.wasm /serai.wasm
# By default, copy the artifact to `/volume`, presumably a provided volume
CMD ["busybox", "cp", "/serai.wasm", "/volume/serai.wasm"]
