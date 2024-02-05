use std::{path::Path};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn message_queue(orchestration_path: &Path, network: Network) {
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service(network.release(), network.db(), "serai-message-queue");

  let env_vars = [
    ("COORDINATOR_KEY", ""),
    ("BITCOIN_KEY", ""),
    ("ETHEREUM_KEY", ""),
    ("MONERO_KEY", ""),
    ("DB_PATH", "./message-queue-db"),
    ("RUST_LOG", "serai_message_queue=trace"),
  ];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    env_vars_str += &format!(r#"{env_var}="${{{env_var}:='{value}'}}" "#);
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

  let run = os(Os::Debian, "", "messagequeue") + &run_message_queue;
  let res = setup + &run;

  let mut message_queue_path = orchestration_path.to_path_buf();
  message_queue_path.push("message-queue");
  message_queue_path.push("Dockerfile");

  write_dockerfile(message_queue_path, &res);
}
