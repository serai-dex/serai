# Configure Environment
FROM alpine:latest

ENV GETH_VERSION=1.10.23
ENV GLIBC_VERSION=2.28-r0

WORKDIR /opt/ethereum

# Get Binary
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
	&& wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-${GLIBC_VERSION}.apk \
	&& wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-bin-${GLIBC_VERSION}.apk

RUN apk update \
	&& apk --no-cache add ca-certificates gnupg bash su-exec \
	&& apk --no-cache add glibc-${GLIBC_VERSION}.apk \
	&& apk --no-cache add glibc-bin-${GLIBC_VERSION}.apk

RUN mkdir ethereum \
    && cd ethereum

RUN wget https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-${GETH_VERSION}-d901d853.tar.gz\
	&& wget https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-${GETH_VERSION}-d901d853.tar.gz.asc

# Verify Binary
# refer to https://geth.ethereum.org/downloads/#openpgp_signatures
# for the PGP keys of builders and developers
ENV KEYS F9585DE6 C2FF8BBF 9BA28146 7B9E2481 D2A67EAC E058A81C 05A5DDF0 1CCB7DD2

RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ${KEYS} \
	&& gpg --verify geth-linux-amd64-${GETH_VERSION}-d901d853.tar.gz.asc geth-linux-amd64-${GETH_VERSION}-d901d853.tar.gz

# Prepare Image
RUN tar xzvf geth-linux-amd64-${GETH_VERSION}-d901d853.tar.gz \
	&& mkdir /root/.ethereum \
	&& mv geth-linux-amd64-${GETH_VERSION}-d901d853/* /usr/local/bin/ \
	&& apk del wget ca-certificates \
    && cd .. \
	&& rm -rf ethereum* \
	&& rm -rf glibc-*

RUN adduser -S ethereum

EXPOSE 8545 8546 30303 30303/udp

# Run
CMD ["geth"]
