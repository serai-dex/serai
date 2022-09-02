FROM docker.io/paritytech/ci-linux:production as builder
LABEL description="STAGE 1: Build"

# Add files for build
ADD substrate /serai/substrate
ADD processor /serai/processor
ADD coins /serai/coins
ADD crypto /serai/crypto
ADD contracts /serai/contracts
ADD Cargo.toml /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Update Rust
RUN rustup update

# Install Solc @ 0.8.16
RUN pip3 install solc-select
RUN solc-select install 0.8.16
RUN solc-select use 0.8.16

# Build it
RUN cargo build --release

# Mount for Cache
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/serai/target

# Prepare Image
FROM ubuntu:latest as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/serai

# Copy necessary files to run node
COPY --from=builder /serai/target/release/* /bin/
COPY --from=builder /serai/AGPL-3.0 .

# Run node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
