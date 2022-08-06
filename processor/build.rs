use std::{
  io::Write,
  env,
  path::{Path, PathBuf},
  fs::{File, remove_file},
  process::Command,
};

#[must_use]
fn subxt(metadata: &Path) -> bool {
  let mut subxt = Command::new("subxt");
  subxt.args(&["metadata", "-f", "bytes"]);
  if !subxt.status().unwrap().success() {
    return false;
  }

  File::create(metadata).unwrap().write_all(&subxt.output().unwrap().stdout).unwrap();

  // Rerun if any further changes to the metadata file (such as deletion) occur
  println!("cargo:rerun-if-changed={}", metadata.display());

  true
}

fn metadata() -> PathBuf {
  let metadata = Path::new(&env::var("OUT_DIR").unwrap()).join("serai.scale");

  let node = format!("../target/{}/serai-node", env::var("PROFILE").unwrap());
  // Re-run whenever a new Serai node version exists
  println!("cargo:rerun-if-changed={}", node);

  // Remove any existing file
  let _ = remove_file(&metadata);

  // If we can run subxt now (as a node is already running), do so
  if subxt(&metadata) {
    return metadata;
  }

  // Run a task, running it every 10 seconds for the specified amount of minutes
  let run_for_minutes = |minutes, task: &mut dyn FnMut() -> bool| {
    for _ in 0 .. (minutes * 6) {
      if task() {
        break;
      }

      std::thread::sleep(std::time::Duration::from_secs(10));
    }
  };

  // If the node doesn't exist, wait for it to
  // Wait up to 2 hours as a fresh build may take that long
  // TODO: Replace this with https://github.com/rust-lang/cargo/issues/9096
  run_for_minutes(2 * 60, &mut || Path::new(&node).exists());

  // If it now exists, run it
  // If it doesn't, this will error, and we can move on
  let mut node = Command::new(node).arg("--dev").spawn().unwrap();

  // Run subxt until either it succeeds or the node fails, with a 5 minute maximum
  let mut task = || subxt(&metadata) || node.try_wait().unwrap().is_some();
  run_for_minutes(5, &mut task);

  // Kill the node
  node.kill().expect("serai-node wasn't running. Did it crash?");

  // Ensure the metadata file exists
  if !metadata.exists() {
    panic!("failed to download metadata within 5 minutes");
  }

  metadata
}

fn main() {
  let metadata = metadata();

  let runtime = Path::new(&env::var("OUT_DIR").unwrap()).join("runtime.rs");
  let _ = remove_file(&runtime);
  File::create(&runtime)
    .unwrap()
    .write_all(
      &format!(
        "
          #[subxt::subxt(runtime_metadata_path = \"{}\")]
          mod runtime {{}}
        ",
        metadata.display()
      )
      .as_bytes(),
    )
    .unwrap();

  println!("cargo:rerun-if-changed={}", runtime.display());
}
