#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::{path::PathBuf, fs, process::Command};

/// Build contracts from the specified path, outputting the artifacts to the specified path.
///
/// Requires solc 0.8.29.
pub fn build(
  include_paths: &[&str],
  contracts_path: &str,
  artifacts_path: &str,
) -> Result<(), String> {
  if !fs::exists(artifacts_path)
    .map_err(|e| format!("couldn't check if artifacts directory already exists: {e:?}"))?
  {
    fs::create_dir_all(artifacts_path)
      .map_err(|e| format!("couldn't create the non-existent artifacts directory: {e:?}"))?;
  }

  println!("cargo:rerun-if-changed={contracts_path}/*");
  println!("cargo:rerun-if-changed={artifacts_path}/*");

  for line in String::from_utf8(
    Command::new("solc")
      .args(["--version"])
      .output()
      .map_err(|_| "couldn't fetch solc output".to_owned())?
      .stdout,
  )
  .map_err(|_| "solc stdout wasn't UTF-8")?
  .lines()
  {
    if let Some(version) = line.strip_prefix("Version: ") {
      let version =
        version.split('+').next().ok_or_else(|| "no value present on line".to_owned())?;
      if version != "0.8.29" {
        Err(format!("version was {version}, 0.8.29 required"))?;
      }
    }
  }

  #[rustfmt::skip]
  let mut args = vec![
    "--base-path", ".",
    "-o", artifacts_path, "--overwrite",
    "--bin", "--bin-runtime", "--abi",
    "--via-ir", "--optimize",
    "--no-color",
  ];
  for include_path in include_paths {
    args.push("--include-path");
    args.push(include_path);
  }
  let mut args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();

  let mut queue = vec![PathBuf::from(contracts_path)];
  while let Some(folder) = queue.pop() {
    for entry in fs::read_dir(folder).map_err(|e| format!("couldn't read directory: {e:?}"))? {
      let entry = entry.map_err(|e| format!("couldn't read directory in entry: {e:?}"))?;
      let kind = entry.file_type().map_err(|e| format!("couldn't fetch file type: {e:?}"))?;
      if kind.is_dir() {
        queue.push(entry.path());
      }

      if (!kind.is_dir()) &&
        entry
          .file_name()
          .into_string()
          .map_err(|_| "file name wasn't a valid UTF-8 string".to_owned())?
          .ends_with(".sol")
      {
        args.push(
          entry
            .path()
            .into_os_string()
            .into_string()
            .map_err(|_| "file path wasn't a valid UTF-8 string".to_owned())?,
        );
      }

      // We on purposely ignore symlinks to avoid recursive structures
    }
  }

  let solc = Command::new("solc")
    .args(args.clone())
    .output()
    .map_err(|_| "couldn't fetch solc output".to_owned())?;
  let stderr = String::from_utf8(solc.stderr).map_err(|_| "solc stderr wasn't UTF-8".to_owned())?;
  if !solc.status.success() {
    Err(format!("solc (`{}`) didn't successfully execute: {stderr}", args.join(" ")))?;
  }
  for line in stderr.lines() {
    if line.contains("Error:") {
      Err(format!("solc (`{}`) output had error: {stderr}", args.join(" ")))?;
    }
  }

  Ok(())
}
