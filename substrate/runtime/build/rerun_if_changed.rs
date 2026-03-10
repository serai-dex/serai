use std::collections::HashSet;

use super::*;

/*
  Re-run anytime the dependencies change.

  We detect if the dependencies change by using if the `Cargo.lock` changed. This isn't
  fine-grained, as it covers the entire Serai workspace, but there isn't another way to check if
  the dependencies changed we can't tell `cargo` to rerun if the output of
  `cargo tree -p serai-runtime` changes. We could implement such detection ourselves, but it
  isn't worth the complexity at this time.

  TODO(never): If reran yet everything is the same except the `Cargo.lock`, compare the subtree
  for `serai-runtime` specifically ourselves. This would avoid rebuilds because a
  not-in-`serai-runtime`-tree dependency was updated.

  Then, for all crates specified by file path, we re-run if their directories change. This assumes
  dependencies aren't dependent on files which live outside their own directories (or a directory
  of another dependency).

  The usage of `cargo tree` is sub-optimal in that `cargo tree` is intended for human consumption
  and may? not have a stable definition. We accept this here. Alternatively, we could use
  `cargo metadata` (with a defined, stable format), but the complexity of parsing its JSON isn't
  worth the benefit when `cargo tree` performs the exact filtering we want and its format is
  simple enough to parse (solely unstable).

  TODO(never): Now that we have `core-json` as a dependency, properly parse the structured output.
*/
pub(super) fn rerun_if_changed(features_flag: &str) {
  let mut rerun_if_changed = HashSet::new();
  rerun_if_changed.insert(workspace_dir().join("Cargo.lock"));

  let tree_command = || {
    let mut command = cargo_command();
    command.arg("tree").args(["--prefix", "none", "--color", "never", "--charset", "utf8"]);
    command
  };

  // Note this subtree includes `serai-runtime` itself, so this will be reran if this changes
  let runtime_subtree = tree_command()
    .args(["-p", "serai-runtime"])
    .args(["--edges", "no-dev"])
    .args(["--target", "wasm32v1-none"])
    .args(["--no-default-features", features_flag])
    .output()
    .expect("failed to get dependency tree for `serai-runtime`");
  assert!(runtime_subtree.status.success());
  let runtime_subtree = String::from_utf8(runtime_subtree.stdout)
    .expect("`cargo tree` with UTF-8 charset wasn't UTF-8");

  for dep in runtime_subtree.lines() {
    let mut parts = dep.split(' ');

    let crate_name = parts.next().expect("line in `cargo tree` output omitted crate name");
    let crate_version = parts.next().expect("line in `cargo tree` output omitted crate name");

    /*
      `cargo tree`, as configured above, will output any subtype next (such `proc-macro`). It
      will then proceed to output the source, if not crates.io, before outputting if a wildcard
      version specification was used.

      Unfortunately, it doesn't let us distinguish what the text was intended to be, forcing us
      to detect it ad-hoc. We iterate all remaining parts and if any are paths on our filesystem,
      we check if they correspond to the crate we're looking for using a `cargo tree` command.
    */
    for part in parts {
      /*
        If this 'crate' doesn't exist, or we can't access it, this isn't what we're looking for.
        This shouldn't be necessary as we proceed to check this path with an invocation of
        `cargo`, but it's better to check this is a path before we start calling an executable
        with it as input.
      */
      let (folder, would_be_manifest) = {
        let mut possible_folder = PathBuf::from(
          part
            .strip_prefix('(')
            .expect("contextual part of `cargo tree` omitted opening parentheses")
            .strip_suffix(')')
            .expect("contextual part of `cargo tree` omitted closing parentheses"),
        );

        // `cargo tree` was invoked from `workspace_dir()`, so ensure that context is respected
        if possible_folder.is_relative() {
          possible_folder = workspace_dir().join(possible_folder);
        }
        assert!(possible_folder.is_absolute());

        let would_be_manifest = possible_folder.join("Cargo.toml");
        let manifest_exists_and_is_accessible = matches!(fs::exists(&would_be_manifest), Ok(true));
        if !manifest_exists_and_is_accessible {
          continue;
        }
        (possible_folder, would_be_manifest)
      };
      let would_be_manifest = would_be_manifest
        .into_os_string()
        .into_string()
        .expect("UTF-8 string -> path -> string failed");

      // Get the ID of the corresponding crate for this (would-be) manifest via `cargo`
      let possible_crate = tree_command()
        .args(["--manifest-path", &would_be_manifest])
        .args(["--depth", "0"])
        .output()
        .expect("failed to spawn `cargo tree` command for possible path of dependency");
      // If `cargo` didn't succeed, this obviously wasn't a properly-defined crate
      if !possible_crate.status.success() {
        continue;
      }

      // The first line, and only line due to `--depth 0`, should be this crate's ID
      let this_crate = String::from_utf8(possible_crate.stdout)
        .expect("`cargo tree` with UTF-8 charset wasn't UTF-8");
      let mut this_crate_parts = this_crate.split(' ');
      let this_crate_name = this_crate_parts.next().expect("`cargo tree` omitted name of dep");
      let this_crate_version =
        this_crate_parts.next().expect("`cargo tree` omitted version of dep");
      if (this_crate_name == crate_name) && (this_crate_version == crate_version) {
        // Re-run if this directory changes
        rerun_if_changed.insert(folder);
        break;
      }
    }
  }

  for path in rerun_if_changed {
    // We require this path be absolute so we aren't concerned about the working directory
    // `cargo` applies to `rerun-if-changed` directives (the crate itself's root)
    assert!(path.is_absolute());
    println!("cargo::rerun-if-changed={}", path.display());
  }
}
