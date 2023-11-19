FROM debian:bookworm-slim as mimalloc

RUN apt update && apt upgrade -y && apt install -y gcc g++ make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so
FROM rust:1.74-slim-bookworm as builder

COPY --from=mimalloc libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean

# Add dev dependencies
RUN apt install -y pkg-config clang

# Dependencies for the Serai node
RUN apt install -y make protobuf-compiler

# Add files for build
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD substrate /serai/substrate
ADD mini /serai/mini
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/serai/target \
  mkdir /serai/bin && \
  cargo build --release -p serai-node && \
  mv /serai/target/release/serai-node /serai/bin
FROM debian:bookworm-slim as image

COPY --from=mimalloc libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean
# Switch to a non-root user
RUN useradd --system --home /home/serai --shell /sbin/nologin serai
USER serai

WORKDIR /home/serai

# Copy the Serai binary and relevant license
COPY --from=builder --chown=serai /serai/bin/serai-node /bin/
COPY --from=builder --chown=serai /serai/AGPL-3.0 .

# Run node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
