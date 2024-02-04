use std::{path::Path};

use crate::{Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn serai(orchestration_path: &Path) {
  let setup = mimalloc(Os::Debian).to_string() + &build_serai_service(true, "", "serai-node");

  // TODO: Review the ports exposed here
  const RUN_SERAI: &str = r#"
# Copy the Serai binary and relevant license
COPY --from=builder --chown=serai /serai/bin/serai-node /bin/
COPY --from=builder --chown=serai /serai/AGPL-3.0 .

# Run the Serai node
EXPOSE 30333 9615 9933 9944

ADD scripts /scripts
CMD ["./scripts/entry-dev.sh"]
"#;

  let run = os(Os::Debian, "", "serai") + RUN_SERAI;
  let res = setup + &run;

  let mut serai_path = orchestration_path.to_path_buf();
  serai_path.push("serai");
  serai_path.push("Dockerfile");

  write_dockerfile(serai_path, &res);
}
