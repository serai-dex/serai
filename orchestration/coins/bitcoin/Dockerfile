# Configure Environment
FROM alpine:latest as builder

ENV BITCOIN_VERSION=25.0
ENV GLIBC_VERSION=2.28-r0
ENV BITCOIN_DATA=/home/bitcoin/.bitcoin

WORKDIR /home/bitcoin

RUN apk update && \
  apk --no-cache add ca-certificates bash su-exec git gnupg

# Download Bitcoin
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz \
  && wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS \
  && wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc

# Verify all sigs and check for a valid signature from laanwj -- 71A3
RUN git clone https://github.com/bitcoin-core/guix.sigs && \
  cd guix.sigs/builder-keys && \
  find . -iname '*.gpg' -exec gpg --import {} \; && \
  gpg --verify --status-fd 1 --verify ../../SHA256SUMS.asc ../../SHA256SUMS | grep "^\[GNUPG:\] VALIDSIG.*71A3B16735405025D447E8F274810B012346C9A6"

RUN grep bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz SHA256SUMS | sha256sum -c

# Prepare Image
RUN tar xzvf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz
RUN mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind .

FROM debian:bookworm-slim as image

# Upgrade packages
RUN apt update && apt upgrade -y

# Switch to a non-root user
RUN useradd --system --create-home --shell /sbin/nologin bitcoin
USER bitcoin
WORKDIR /home/bitcoin

COPY --from=builder --chown=bitcoin /home/bitcoin/bitcoind /bin
COPY ./scripts /scripts

EXPOSE 8332 8333 18332 18333 18443 18444
# VOLUME ["/home/bitcoin/.bitcoin"]
