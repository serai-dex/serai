use std::{path::Path, io::Write, fs::File};

use crate::{Os, mimalloc, os, build_serai_service};

pub fn coordinator(orchestration_path: &Path) {
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service(false, "parity-db longer-reattempts", "serai-coordinator");

  const ADDITIONAL_ROOT: &str = r#"
# Install ca-certificates
RUN apt install -y ca-certificates
"#;

  const RUN_COORDINATOR: &str = r#"
# Copy the Coordinator binary and relevant license
COPY --from=builder --chown=coordinator /serai/bin/serai-coordinator /bin/
COPY --from=builder --chown=coordinator /serai/AGPL-3.0 .

# Run coordinator
CMD ["serai-coordinator"]
"#;

  let run = os(Os::Debian, ADDITIONAL_ROOT, "coordinator") + RUN_COORDINATOR;
  let res = setup + &run;

  let mut coordinator_path = orchestration_path.to_path_buf();
  coordinator_path.push("coordinator");
  coordinator_path.push("Dockerfile");

  File::create(coordinator_path).unwrap().write_all(res.as_bytes()).unwrap();
}
