# Prepare Environment
FROM alpine:latest as builder

ENV GETH_VERSION=1.10.23-d901d853

WORKDIR /home/ethereum

RUN apk update \
	&& apk --no-cache add ca-certificates gnupg bash su-exec

# Get Binary
RUN wget https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-${GETH_VERSION}.tar.gz\
	&& wget https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-${GETH_VERSION}.tar.gz.asc

# Verify Binary
# refer to https://geth.ethereum.org/downloads/#openpgp_signatures
# for the PGP keys of builders and developers
ENV KEYS 9BA28146 E058A81C 05A5DDF0 1CCB7DD2

RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ${KEYS} \
	&& gpg --verify geth-linux-amd64-${GETH_VERSION}.tar.gz.asc geth-linux-amd64-${GETH_VERSION}.tar.gz

# Prepare Image
RUN tar xzvf geth-linux-amd64-${GETH_VERSION}.tar.gz

# Prepare Image
FROM ubuntu:latest as image

WORKDIR /home/ethereum
COPY --from=builder /home/ethereum/* .
RUN mv * /bin/
COPY ./scripts /scripts

EXPOSE 8545 8546 30303 30303/udp

# Run
CMD ["geth"]
