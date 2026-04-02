use std::path::Path;

use crate::{Network, Os, mimalloc, os, write_dockerfile};

pub fn bitcoin(orchestration_path: &Path, network: Network) {
  const VERSION: &str = "30.2";
  let file = format!("bitcoin-{VERSION}-$(uname -m)-linux-gnu.tar.gz");
  let url = format!("https://bitcoincore.org/bin/bitcoin-core-{VERSION}");

  // laanwj
  const FINGERPRINT: &str = "71A3B16735405025D447E8F274810B012346C9A6";

  #[rustfmt::skip]
  let download_bitcoin = format!(r#"
FROM alpine:latest AS download

RUN apk --no-cache add git

# Download Bitcoin
RUN wget {url}/{file}

# Extract Bitcoin
RUN tar -xf "{file}"
RUN mv $(find . -name bitcoind) .

# Download the hashes, signature from laanwj
RUN git clone --depth 1 https://github.com/bitcoin-core/guix.sigs
RUN cp guix.sigs/{VERSION}/laanwj/all.SHA256SUMS SHA256SUMS
RUN cp guix.sigs/{VERSION}/laanwj/all.SHA256SUMS.asc SHA256SUMS.asc

# Verify `SHA256SUMS` with GnuPG
FROM alpine:latest AS gnupg
RUN apk --no-cache add gnupg
RUN mkdir ~/.gnupg # Prevent the default config of `use-keyboxd`
COPY --from=download SHA256SUMS SHA256SUMS.asc /
RUN gpg --keyserver hkps://keyserver.ubuntu.com --keyserver-options no-self-sigs-only --receive-keys {FINGERPRINT}
RUN gpg --verify SHA256SUMS.asc SHA256SUMS
RUN touch /tmp/done

# Verify `SHA256SUMS` with Sequoia PGP
FROM alpine:latest AS sequoia
RUN apk --no-cache add sequoia-sq
COPY --from=download SHA256SUMS SHA256SUMS.asc /
RUN sq network keyserver search --server hkps://keyserver.ubuntu.com {FINGERPRINT}
RUN sq pki link add --cert {FINGERPRINT} --all
RUN sq verify --signature-file SHA256SUMS.asc SHA256SUMS
RUN touch /tmp/done

# Verify the integrity of `bitcoin-*.tar.gz` with regards to the `SHA256SUMS` file
FROM alpine:latest AS sha256sum
COPY --from=download *.tar.gz SHA256SUMS /
# Parse to just the hash for the one file we downloaded
RUN echo $(grep "{file}" SHA256SUMS) > SHA256SUMS
# Ensure we successfully grabbed the line in question
RUN if [ $(wc -l SHA256SUMS) -ne 1 ]; then exit 1; fi
RUN cat SHA256SUMS | sha256sum -c
RUN touch /tmp/done
"#);

  let setup = mimalloc(Os::Alpine, true) + &download_bitcoin;

  let run_bitcoin = format!(
    r#"
# Require successful executions of the verification steps
COPY --from=sha256sum /tmp/done /tmp/done
COPY --from=gnupg /tmp/done /tmp/done
COPY --from=sequoia --chown=bitcoin /tmp/done /tmp/done
RUN rm /tmp/done

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
