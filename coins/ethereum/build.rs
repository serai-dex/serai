use ethers_solc::{Project, ProjectPathsConfig};

fn main() {
  println!("cargo:rerun-if-changed=contracts");
  println!("cargo:rerun-if-changed=artifacts");

  // configure the project with all its paths, solc, cache etc.
  let project = Project::builder()
    .paths(ProjectPathsConfig::hardhat(env!("CARGO_MANIFEST_DIR")).unwrap())
    .build()
    .unwrap();
  project.compile().unwrap();

  // Tell Cargo that if a source file changes, to rerun this build script.
  project.rerun_if_sources_changed();
}
