use std::{path::Path};

use zeroize::Zeroizing;

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

#[allow(clippy::needless_pass_by_value)]
pub fn processor(
  orchestration_path: &Path,
  network: Network,
  coin: &'static str,
  _coordinator_key: <Ristretto as Ciphersuite>::G,
  coin_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  entropy: Zeroizing<[u8; 32]>,
) {
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service(
      Os::Debian,
      network.release(),
      &format!("binaries {} {coin}", network.db()),
      "serai-processor",
    );

  const ADDITIONAL_ROOT: &str = r#"
# Install ca-certificates
RUN apt install -y ca-certificates
"#;

  // TODO: Randomly generate these
  const RPC_USER: &str = "serai";
  const RPC_PASS: &str = "seraidex";
  // TODO: Isolate networks
  let hostname = format!("serai-{}-{coin}", network.label());
  let port = match coin {
    "bitcoin" => 8332,
    "ethereum" => return, // TODO
    "monero" => 18081,
    _ => panic!("unrecognized external network"),
  };

  let env_vars = [
    ("MESSAGE_QUEUE_RPC", format!("serai-{}-message_queue", network.label())),
    ("MESSAGE_QUEUE_KEY", hex::encode(coin_key.to_repr())),
    ("ENTROPY", hex::encode(entropy.as_ref())),
    ("NETWORK", coin.to_string()),
    ("NETWORK_RPC_LOGIN", format!("{RPC_USER}:{RPC_PASS}")),
    ("NETWORK_RPC_HOSTNAME", hostname),
    ("NETWORK_RPC_PORT", format!("{port}")),
    ("DB_PATH", "./processor-db".to_string()),
    ("RUST_LOG", "serai_processor=debug".to_string()),
  ];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    env_vars_str += &format!(r#"{env_var}=${{{env_var}:="{value}"}} "#);
  }

  let run_processor = format!(
    r#"
# Copy the Processor binary and relevant license
COPY --from=builder --chown=processor /serai/bin/serai-processor /bin/
COPY --from=builder --chown=processor /serai/AGPL-3.0 .

# Run processor
CMD {env_vars_str} serai-processor
"#
  );

  let run = os(Os::Debian, ADDITIONAL_ROOT, "processor") + &run_processor;
  let res = setup + &run;

  let mut processor_path = orchestration_path.to_path_buf();
  processor_path.push("processor");
  processor_path.push(coin);
  processor_path.push("Dockerfile");

  write_dockerfile(processor_path, &res);
}
