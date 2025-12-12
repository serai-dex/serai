use core::fmt::Write;
use std::path::Path;

use dalek_ff_group::Ristretto;
use ciphersuite::{group::GroupEncoding, WrappedGroup};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn message_queue(
  orchestration_path: &Path,
  network: Network,
  coordinator_key: <Ristretto as WrappedGroup>::G,
  bitcoin_key: <Ristretto as WrappedGroup>::G,
  ethereum_key: <Ristretto as WrappedGroup>::G,
  monero_key: <Ristretto as WrappedGroup>::G,
) {
  let setup = mimalloc(Os::Alpine) +
    &build_serai_service("", Os::Alpine, network.release(), network.db(), "serai-message-queue");

  let env_vars = [
    ("COORDINATOR_KEY", hex::encode(coordinator_key.to_bytes())),
    ("BITCOIN_KEY", hex::encode(bitcoin_key.to_bytes())),
    ("ETHEREUM_KEY", hex::encode(ethereum_key.to_bytes())),
    ("MONERO_KEY", hex::encode(monero_key.to_bytes())),
    ("DB_PATH", "/volume/message-queue-db".to_owned()),
    ("RUST_LOG", "info,serai_message_queue=trace".to_owned()),
  ];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    write!(&mut env_vars_str, r#"{env_var}=${{{env_var}:="{value}"}} "#).unwrap();
  }

  let run_message_queue = format!(
    r#"
# Copy the Message Queue binary and relevant license
COPY --from=builder --chown=messagequeue /serai/bin/serai-message-queue /bin
COPY --from=builder --chown=messagequeue /serai/AGPL-3.0 .

# Run message-queue
EXPOSE 2287
CMD {env_vars_str} serai-message-queue
"#
  );

  let run = os(Os::Alpine, "", "messagequeue") + &run_message_queue;
  let res = setup + &run;

  let mut message_queue_path = orchestration_path.to_path_buf();
  message_queue_path.push("message-queue");
  message_queue_path.push("Dockerfile");

  write_dockerfile(message_queue_path, &res);
}
