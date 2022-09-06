# Configure Environment
FROM alpine:latest as builder

ENV BITCOIN_VERSION=23.0
ENV GLIBC_VERSION=2.28-r0
ENV SIG_REQ=3
ENV BITCOIN_DATA=/home/bitcoin/.bitcoin

WORKDIR /home/bitcoin


RUN apk update \
	&& apk --no-cache add ca-certificates gnupg bash su-exec 

SHELL ["/bin/bash", "-c"]
# Get Binary
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz \
	&& wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS \
	&& wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc

# Verify Binary
# For the PGP keys of builders and developers, refer to 
# https://github.com/bitcoin/bitcoin/tree/master/contrib/builder-keys
# Serai recognizes a handselected reduced set of keys from the list, prefixes -- 
# marco -- B8B3
# laanwj -- 71A3
# fanquake -- E777
# achow101 -- 1528
# glozow -- 6B00
# hebasto -- D1DB
ENV KEYS  B8B3F1C0E58C15DB6A81D30C3648A882F4316B9B 71A3B16735405025D447E8F274810B012346C9A6 E777299FC265DD04793070EB944D35F9AC3DB76A
ENV KEYS2 152812300785C96444D3334D17565732E08E5E41 6B002C6EA3F91B1B0DF0C9BC8F617F1200A6D25C D1DBF2C4B96F2DEBF4C16654410108112E7EA81F

# Use footprints to get keys from servers. 2 Different servers used.
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ${KEYS} \
	&& gpg --keyserver hkp://keys.openpgp.org:80 --recv-keys ${KEYS2}

# Capture error output and count good signature occurrence
# if above threshold continue
# else exit code 2
RUN { err="$( { gpg --verify --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS; } 2>&1 >&3 3>&- )"; } 3>&1; num="$(echo $err | grep -o 'Good signature' | wc -l)" \
	&& if (($num > ${SIG_REQ} )); then echo "Signatures found: $num. Above threshold of ${SIG_REQ}!"; else exit 2; fi

RUN grep bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz SHA256SUMS | sha256sum -c

# Prepare Image
RUN tar xzvf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz

# Prepare Image
FROM ubuntu:latest as image
WORKDIR /home/bitcoin
COPY --from=builder /home/bitcoin/* .

RUN mv bin/* /bin \
&& mv lib/* /lib \
&& mv share/* /share

COPY ./scripts /scripts

EXPOSE 8332 8333 18332 18333 18443 18444
VOLUME ["/home/bitcoin/.bitcoin"]

# Run
CMD ["bitcoind"]
