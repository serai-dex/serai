use core::fmt::Write as _;
use std::path::Path;

use crate::{Network, Os, mimalloc, os, write_dockerfile};

pub fn bitcoin(orchestration_path: &Path, network: Network) {
  const VERSION: &str = "31.0";
  let file = format!("bitcoin-{VERSION}-$(uname -m)-linux-gnu.tar.gz");
  let url = format!("https://bitcoincore.org/bin/bitcoin-core-{VERSION}");

  #[rustfmt::skip]
  let mut download_bitcoin = format!(r#"
FROM alpine:latest AS download

RUN apk --no-cache add git

# Download Bitcoin
RUN wget {url}/{file}

# Extract Bitcoin
RUN tar -xf "{file}"
RUN mv $(find . -name bitcoind) .

# Download the hashes, signatures
RUN git clone --depth 1 https://github.com/bitcoin-core/guix.sigs
"#);

  let mut run_bitcoin_first = String::new();
  let mut run_bitcoin_second = r#"
RUN <<'EOF'
  set -eux
  COUNT=0
"#
  .to_owned();

  let signers = [
    ("laanwj", "71A3B16735405025D447E8F274810B012346C9A6"),
    ("fanquake", "E777299FC265DD04793070EB944D35F9AC3DB76A"),
    ("achow101", "152812300785C96444D3334D17565732E08E5E41"),
  ];
  for (username, fingerprint) in signers {
    write!(
      &mut download_bitcoin,
      r#"
# Verify `SHA256SUMS` with GnuPG
FROM alpine:latest AS gnupg-{username}
RUN apk --no-cache add gnupg
RUN mkdir ~/.gnupg # Prevent the default config of `use-keyboxd`
COPY --from=download guix.sigs /guix.sigs
RUN <<'EOF'
  set -eux
  mkdir -p /tmp
  if [ ! -d "/guix.sigs/{VERSION}/{username}" ]; then exit 0; fi

  cp guix.sigs/{VERSION}/{username}/all.SHA256SUMS SHA256SUMS
  cp guix.sigs/{VERSION}/{username}/all.SHA256SUMS.asc SHA256SUMS.asc
  gpg --keyserver hkps://keyserver.ubuntu.com --keyserver-options no-self-sigs-only \
    --receive-keys {fingerprint}
  gpg --verify SHA256SUMS.asc SHA256SUMS
  touch /tmp/gnupg-{username}
EOF

# Verify `SHA256SUMS` with Sequoia PGP
FROM alpine:latest AS sequoia-{username}
RUN apk --no-cache add sequoia-sq
COPY --from=download guix.sigs /guix.sigs
RUN <<'EOF'
  set -eux
  mkdir -p /tmp
  if [ ! -d "/guix.sigs/{VERSION}/{username}" ]; then exit 0; fi

  cp guix.sigs/{VERSION}/{username}/all.SHA256SUMS SHA256SUMS
  cp guix.sigs/{VERSION}/{username}/all.SHA256SUMS.asc SHA256SUMS.asc
  sq network keyserver search --server hkps://keyserver.ubuntu.com {fingerprint}
  sq pki link add --cert {fingerprint} --all
  sq verify --signature-file SHA256SUMS.asc SHA256SUMS
  touch /tmp/sequoia-{username}
EOF

# Verify the integrity of `bitcoin-*.tar.gz` with regards to the `SHA256SUMS` file
FROM alpine:latest AS sha256sum-{username}
COPY --from=download *.tar.gz /
COPY --from=download guix.sigs /guix.sigs
RUN <<'EOF'
  set -eux
  mkdir -p /tmp
  if [ ! -d "/guix.sigs/{VERSION}/{username}" ]; then exit 0; fi

  cp guix.sigs/{VERSION}/{username}/all.SHA256SUMS SHA256SUMS
  # Parse to just the hash for the one file we downloaded
  echo $(grep "{file}" SHA256SUMS) > SHA256SUMS
  # Ensure we successfully grabbed the line in question
  if [ $(wc -l SHA256SUMS) -ne 1 ]; then exit 1; fi
  cat SHA256SUMS | sha256sum -c
  touch /tmp/sha256sum-{username}
EOF
"#
    )
    .unwrap();

    write!(
      &mut run_bitcoin_first,
      r#"
# Require successful executions of the verification steps
RUN mkdir -p /tmp
# Use a wildcard to allow for if the file doesn't exist
COPY --chown=bitcoin --from=gnupg-{username} /tmp/*gnupg-{username} /tmp/
COPY --chown=bitcoin --from=sequoia-{username} /tmp/*sequoia-{username} /tmp/
COPY --chown=bitcoin --from=sha256sum-{username} /tmp/*sha256sum-{username} /tmp/
"#
    )
    .unwrap();

    write!(
      &mut run_bitcoin_second,
      r#"
  if [ -f /tmp/gnupg-{username} ]; then
    if [ ! -f /tmp/sequoia-{username} ]; then exit 1; fi
    if [ ! -f /tmp/sha256sum-{username} ]; then exit 1; fi
    COUNT=$(( $COUNT + 1 ))
  fi
"#
    )
    .unwrap();
  }

  write!(
    &mut run_bitcoin_second,
    r#"
  if [ $COUNT -lt {} ]; then exit 1; fi
  rm -rf /tmp/*
EOF
"#,
    signers.len() - 1
  )
  .unwrap();

  let setup = mimalloc(Os::Alpine, true) + &download_bitcoin;

  let run_bitcoin = format!(
    r#"
{run_bitcoin_first}
{run_bitcoin_second}

COPY --from=download --chown=bitcoin bitcoind /usr/bin

EXPOSE 8332 8333

ADD /orchestration/{}/networks/bitcoin/run.sh /
CMD ["/run.sh"]
"#,
    network.label()
  );

  let run = os(Os::Alpine, true, "", "bitcoin") + &run_bitcoin;
  let res = setup + &run;

  let mut bitcoin_path = orchestration_path.to_path_buf();
  bitcoin_path.extend(["networks", "bitcoin", "Dockerfile"]);
  write_dockerfile(bitcoin_path, &res);
}
