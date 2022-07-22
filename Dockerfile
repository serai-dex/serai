#
# serai Docker image
#
# ex: docker build --tag serai .

FROM debian:bullseye-slim as build


## BUILD ENVIRONMENT ##

RUN apt-get update

# Install solc
RUN apt-get install -y python3-pip
RUN pip3 install solc-select
RUN solc-select install 0.8.9
RUN solc-select use 0.8.9

# Install Monero dependencies
RUN apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libboost-all-dev \
    libssl-dev \
    libzmq3-dev \
    libpgm-dev \
    libunbound-dev \
    libsodium-dev \
    ccache

# Install Rust
RUN apt-get install -y curl
RUN curl https://sh.rustup.rs -sSf | sh -s -- --profile minimal --default-toolchain nightly -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install WASM toolchain
RUN rustup update
RUN rustup update nightly
RUN rustup target add wasm32-unknown-unknown --toolchain nightly

# Install other dependencies (git for build.rs)
# FIXME: maybe removing git from build.rs is wise?
RUN apt-get install -y git

# librocksdb-sys errors out without clang
# FIXME: which clang version?
RUN apt-get install -y clang-11

## COMPILATION ##

# Add source code
ADD . /serai
WORKDIR /serai

# Finally build!
#TODO: maybe ARCH and nproc as ARG parameters?
# Takes about 15 minutes to build on a Ryzen 5900HX with 32GB of RAM
RUN ARCH=default cargo build --all-features --release --verbose -j$(nproc)


## ARTIFACTS ##

# Create new Docker layer with just the built files so image is smaller
FROM debian:bullseye-slim

# FIXME: copy only necessary files
COPY --from=build /serai/target/release/serai-node /serai/serai-node

WORKDIR /serai
# FIXME: add ports and arguments...
CMD ./serai-node --version
