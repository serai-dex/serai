use core::fmt::Write as _;
use std::path::Path;

use crate::{Network, Os, mimalloc, write_dockerfile};

pub fn monero(orchestration_path: &Path, network: Network) {
  let os = Os::Alpine;

  const MONERO_VERSION: &str = "0.18.4.4";

  let arch = match std::env::consts::ARCH {
    // We probably would run this without issues yet it's not worth needing to provide support for
    "x86" | "arm" => panic!("unsupported architecture, please download a 64-bit OS"),
    "x86_64" => "x64",
    "aarch64" => "armv8",
    _ => panic!("unsupported architecture"),
  };

  let file = format!("monero-linux-{arch}-v{MONERO_VERSION}.tar.bz2");

  // Fingerprint from https://github.com/monero-project/monero-site/issues/1949
  const FINGERPRINT: &str = "81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92";

  #[rustfmt::skip]
  let mut download_monero = format!(r#"
FROM alpine:latest AS download

# Download Monero
RUN wget https://downloads.getmonero.org/cli/{file}

# Extract Monero
RUN tar -xf {file} --strip-components=1

# Download the binary's hashes
RUN wget https://raw.githubusercontent.com/monero-project/monero-site/73084c47b2ef05c6abc12755839e993baf87755b/downloads/hashes.txt -O SHA256SUMS

# Verify `SHA256SUMS` with GnuPG
FROM alpine:latest AS gnupg
RUN apk --no-cache add gnupg
RUN mkdir ~/.gnupg # Prevent the default config of `use-keyboxd`
COPY --from=download SHA256SUMS /
RUN gpg --keyserver hkps://keyserver.ubuntu.com --keyserver-options no-self-sigs-only --receive-keys {FINGERPRINT}
RUN gpg --decrypt SHA256SUMS > SHA256SUMS.gpg

# Verify `SHA256SUMS` with Sequoia PGP
FROM alpine:latest AS sequoia
RUN apk --no-cache add sequoia-sq
COPY --from=download SHA256SUMS /
RUN sq network keyserver search --server hkps://keyserver.ubuntu.com {FINGERPRINT}
RUN sq pki link add --cert {FINGERPRINT} --all
RUN sq verify --message SHA256SUMS --output SHA256SUMS.sq

# Verify the integrity of `monero-*.tar.bz2` with regards to the `SHA256SUMS` file
FROM alpine:latest AS sha256sum
COPY --from=download *.tar.bz2 /
COPY --from=gnupg SHA256SUMS.gpg /
COPY --from=sequoia SHA256SUMS.sq /

# Make sure GnuPG and Sequoia agree on the contents of `SHA256SUMS`
RUN printf "\n" >> SHA256SUMS.sq
RUN cmp SHA256SUMS.gpg SHA256SUMS.sq

# Parse to just the hash for the one file we downloaded
RUN grep "{file}" SHA256SUMS.sq > SHA256SUMS
# Ensure we successfully grabbed the line in question
RUN if [ $(wc -l SHA256SUMS) -ne 1 ]; then exit 1; fi

RUN cat SHA256SUMS | sha256sum -c
RUN touch /tmp/done

FROM alpine:latest AS monero

# Require successful executions of the verification steps
COPY --from=sha256sum /tmp/done /tmp/done
RUN rm /tmp/done

COPY --from=download monerod .
"#);

  if os == Os::Alpine {
    // Increase the default stack size, as Monero does heavily use its stack
    write!(
      &mut download_monero,
      r#"
ADD orchestration/increase_default_stack_size.sh .
RUN ./increase_default_stack_size.sh monerod
"#
    )
    .unwrap();
  }

  let setup = mimalloc(os) + &download_monero;

  let run_monero = format!(
    r#"
COPY --from=monero --chown=monero:nogroup monerod /bin

EXPOSE 18080 18081

ADD /orchestration/{}/networks/monero/run.sh /
CMD ["/run.sh"]
"#,
    network.label(),
  );

  let run =
    crate::os(os, if os == Os::Alpine { "RUN apk --no-cache add gcompat" } else { "" }, "monero") +
      &run_monero;
  let res = setup + &run;

  let mut monero_path = orchestration_path.to_path_buf();
  monero_path.extend(["networks", "monero", "Dockerfile"]);
  write_dockerfile(monero_path, &res);
}
