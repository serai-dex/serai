use crate::Network;

pub fn lighthouse(network: Network) -> (String, String, String) {
  assert_ne!(network, Network::Dev);

  #[rustfmt::skip]
  const DOWNLOAD_LIGHTHOUSE: &str = r#"
FROM alpine:latest as lighthouse

ENV LIGHTHOUSE_VERSION=5.1.3

RUN apk --no-cache add git gnupg

# Download lighthouse
RUN wget https://github.com/sigp/lighthouse/releases/download/v${LIGHTHOUSE_VERSION}/lighthouse-v${LIGHTHOUSE_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz
RUN wget https://github.com/sigp/lighthouse/releases/download/v${LIGHTHOUSE_VERSION}/lighthouse-v${LIGHTHOUSE_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz.asc

# Verify the signature
gpg --keyserver keyserver.ubuntu.com --recv-keys 15E66D941F697E28F49381F426416DC3F30674B0
gpg --verify lighthouse-v${LIGHTHOUSE_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz.asc lighthouse-v${LIGHTHOUSE_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz

# Extract lighthouse
RUN tar xvf lighthouse-v${LIGHTHOUSE_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz
"#;

  let run_lighthouse = format!(
    r#"
COPY --from=lighthouse --chown=ethereum lighthouse /bin

ADD /orchestration/{}/coins/ethereum/consensus/lighthouse/run.sh /consensus_layer.sh
"#,
    network.label()
  );

  (DOWNLOAD_LIGHTHOUSE.to_string(), String::new(), run_lighthouse)
}
