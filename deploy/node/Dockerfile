FROM docker.io/paritytech/ci-linux:production as builder
LABEL description="STAGE 1: Build"

ENV HOME=/home/root
ADD substrate $HOME/serai/substrate
ADD processor $HOME/serai/processor
ADD coins $HOME/serai/coins
ADD crypto $HOME/serai/crypto
ADD contracts $HOME/serai/contracts
ADD Cargo.toml $HOME/serai
WORKDIR $HOME/serai

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
    --mount=type=cache,target=/home/root/serai/target


FROM docker.io/library/ubuntu:20.04
LABEL description="STAGE 2: Copy and Run"

# Copy necessary files to run node
COPY --from=builder /home/root/serai/target/release /serai

WORKDIR /serai

# Run node
CMD ./serai-node