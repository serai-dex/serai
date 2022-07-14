use ethers_solc::{Project, ProjectPathsConfig};

fn main() {
    // configure the project with all its paths, solc, cache etc.
    let project = Project::builder()
        .paths(ProjectPathsConfig::hardhat(env!("CARGO_MANIFEST_DIR")).unwrap())
        .build()
        .unwrap();
    let _output = project.compile().unwrap();

    // Tell Cargo that if a source file changes, to rerun this build script.
    project.rerun_if_sources_changed();
}
