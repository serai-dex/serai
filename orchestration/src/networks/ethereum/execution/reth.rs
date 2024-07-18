use crate::Network;

pub fn reth(network: Network) -> (String, String, String) {
  assert_ne!(network, Network::Dev);

  #[rustfmt::skip]
  const DOWNLOAD_RETH: &str = r#"
FROM alpine:latest as reth

ENV RETH_VERSION=0.2.0-beta.6

RUN apk --no-cache add git gnupg

# Download reth
RUN wget https://github.com/paradigmxyz/reth/releases/download/v${RETH_VERSION}/reth-v${RETH_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz
RUN wget https://github.com/paradigmxyz/reth/releases/download/v${RETH_VERSION}/reth-v${RETH_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz.asc

# Verify the signature
gpg --keyserver keyserver.ubuntu.com --recv-keys A3AE097C89093A124049DF1F5391A3C4100530B4
gpg --verify reth-v${RETH_VERSION}-$(uname -m).tar.gz.asc reth-v${RETH_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz

# Extract reth
RUN tar xvf reth-v${RETH_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz
"#;

  let run_reth = format!(
    r#"
COPY --from=reth --chown=ethereum reth /bin

EXPOSE 30303 9001 8545

ADD /orchestration/{}/networks/ethereum/execution/reth/run.sh /execution_layer.sh
"#,
    network.label()
  );

  (DOWNLOAD_RETH.to_string(), String::new(), run_reth)
}
