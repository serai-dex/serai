use std::{path::Path};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn serai(orchestration_path: &Path, network: Network) {
  // Always builds in release for performance reasons
  let setup = mimalloc(Os::Debian).to_string() + &build_serai_service(true, "", "serai-node");
  let setup_fast_epoch =
    mimalloc(Os::Debian).to_string() + &build_serai_service(true, "fast-epoch", "serai-node");

  // TODO: Review the ports exposed here
  let run_serai = format!(
    r#"
# Copy the Serai binary and relevant license
COPY --from=builder --chown=serai /serai/bin/serai-node /bin/
COPY --from=builder --chown=serai /serai/AGPL-3.0 .

# Run the Serai node
EXPOSE 30333 9615 9933 9944

ADD /orchestration/{}/serai/run.sh /
CMD ["/run.sh"]
"#,
    network.label(),
  );

  let run = os(Os::Debian, "", "serai") + &run_serai;
  let res = setup + &run;
  let res_fast_epoch = setup_fast_epoch + &run;

  let mut serai_path = orchestration_path.to_path_buf();
  serai_path.push("serai");

  let mut serai_fast_epoch_path = serai_path.clone();

  serai_path.push("Dockerfile");
  serai_fast_epoch_path.push("Dockerfile.fast-epoch");

  write_dockerfile(serai_path, &res);
  write_dockerfile(serai_fast_epoch_path, &res_fast_epoch);
}
