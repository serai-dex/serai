FROM docker.io/paritytech/ci-linux:production as builder
LABEL description="STAGE 1: Build"

# Add files for build
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD processor /serai/processor
ADD contracts /serai/contracts
ADD substrate /serai/substrate
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Update Rust
RUN rustup update

# Install Solc @ 0.8.16
RUN --mount=type=cache,target=/root/.cache/ \
    --mount=type=cache,target=/root/.local/ \
    --mount=type=cache,target=/root/.solc-select \
    pip3 install solc-select==0.2.1
RUN --mount=type=cache,target=/root/.cache/ \
    --mount=type=cache,target=/root/.local/ \
    --mount=type=cache,target=/root/.solc-select \ 
    solc-select install 0.8.16
RUN --mount=type=cache,target=/root/.cache/ \
--mount=type=cache,target=/root/.local/ \
--mount=type=cache,target=/root/.solc-select \
 solc-select use 0.8.16

# Mount cargo and serai cache for Cache & Build
RUN --mount=type=cache,target=/root/.local/ \
    --mount=type=cache,target=/root/.solc-select \
    --mount=type=cache,target=/root/.cache/ \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/serai/target/release/build \
    --mount=type=cache,target=/serai/target/release/deps \
    --mount=type=cache,target=/serai/target/release/.fingerprint \
    --mount=type=cache,target=/serai/target/release/incremental \
    --mount=type=cache,target=/serai/target/release/wbuild \
    --mount=type=cache,target=/serai/target/release/lib* \
    cargo build --release

# Prepare Image
FROM ubuntu:latest as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/serai

# Copy necessary files to run node
COPY --from=builder /serai/target/release/ /bin/
COPY --from=builder /serai/AGPL-3.0 .

# Run node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
