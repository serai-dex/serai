use std::{path::Path};

use crate::{Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn message_queue(orchestration_path: &Path) {
  // TODO: Only use parity-db in a test environment
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service(false, "parity-db", "serai-message-queue");

  const RUN_MESSAGE_QUEUE: &str = r#"
# Copy the Message Queue binary and relevant license
COPY --from=builder --chown=messagequeue /serai/bin/serai-message-queue /bin
COPY --from=builder --chown=messagequeue /serai/AGPL-3.0 .

# Run message-queue
EXPOSE 2287
CMD ["serai-message-queue"]
"#;

  let run = os(Os::Debian, "", "messagequeue") + RUN_MESSAGE_QUEUE;
  let res = setup + &run;

  let mut message_queue_path = orchestration_path.to_path_buf();
  message_queue_path.push("message-queue");
  message_queue_path.push("Dockerfile");

  write_dockerfile(message_queue_path, &res);
}
