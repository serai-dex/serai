use std::{
  sync::{Mutex, LazyLock},
  collections::{HashSet, HashMap},
  time::SystemTime,
  path::PathBuf,
  fs, env,
  process::Command,
};

use dockertest::{LogSource, LogAction, LogPolicy, LogOptions};

pub fn handle(desc: &str) -> String {
  static UNIQUE_ID: LazyLock<Mutex<u16>> = LazyLock::new(|| Mutex::new(0));
  let mut unique_id_lock = UNIQUE_ID.lock().unwrap();
  let unique_id = *unique_id_lock;
  *unique_id_lock += 1;
  format!("{desc}-{unique_id}")
}

pub fn fresh_logs_folder(first: bool, label: &str) -> String {
  let logs_path = [std::env::current_dir().unwrap().to_str().unwrap(), ".test-logs", label]
    .iter()
    .collect::<std::path::PathBuf>();
  if first {
    let _ = fs::remove_dir_all(&logs_path);
    fs::create_dir_all(&logs_path).expect("couldn't create logs directory");
    assert!(
      fs::read_dir(&logs_path).expect("couldn't read the logs folder").next().is_none(),
      "logs folder wasn't empty, despite removing it at the start of the run",
    );
  }
  logs_path.to_str().unwrap().to_string()
}

pub fn log_options(path: String) -> LogOptions {
  LogOptions {
    action: if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
      LogAction::Forward
    } else {
      LogAction::ForwardToFile { path }
    },
    policy: LogPolicy::Always,
    source: LogSource::Both,
  }
}

// TODO: Should `serai-orchestrator` handle building?
pub fn build(name: String) {
  static BUILT: LazyLock<Mutex<HashMap<String, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
  // Only one call to build will acquire this lock
  let mut built_lock = BUILT.lock().unwrap();
  if built_lock.contains_key(&name) {
    // If it was built, return
    return;
  }

  // Else, hold the lock while we build

  // Run the orchestrator to ensure the most recent files exist
  if !Command::new("cargo")
    .arg("run")
    .arg("-p")
    .arg("serai-orchestrator")
    .arg("--")
    .arg("key_gen")
    .arg("dev")
    .spawn()
    .unwrap()
    .wait()
    .unwrap()
    .success()
  {
    panic!("failed to run the orchestrator");
  }

  if !Command::new("cargo")
    .arg("run")
    .arg("-p")
    .arg("serai-orchestrator")
    .arg("--")
    .arg("setup")
    .arg("dev")
    .spawn()
    .unwrap()
    .wait()
    .unwrap()
    .success()
  {
    panic!("failed to run the orchestrator");
  }

  let mut repo_path = PathBuf::from(
    core::str::from_utf8(
      &Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .expect("couldn't locate workspace with `cargo`")
        .stdout,
    )
    .expect("`cargo` outputted non-UTF-8 bytes to `stdout`"),
  );
  repo_path.pop(); // Pop the `Cargo.toml` term

  let mut orchestration_path = repo_path.clone();
  orchestration_path.push("orchestration");
  if name != "runtime" {
    orchestration_path.push("dev");
  }

  let mut dockerfile_path = orchestration_path.clone();
  if HashSet::from(["bitcoin", "ethereum", "ethereum-relayer", "monero"]).contains(name.as_str()) {
    dockerfile_path = dockerfile_path.join("networks");
  }
  if name.contains("-processor") {
    dockerfile_path =
      dockerfile_path.join("processor").join(name.split('-').next().unwrap()).join("Dockerfile");
  } else {
    dockerfile_path = dockerfile_path.join(&name).join("Dockerfile");
  }

  // If this Docker image was created after this repo was last edited, return here
  // This should have better performance than Docker and allows running while offline
  if let Ok(res) = Command::new("docker")
    .arg("inspect")
    .arg("-f")
    .arg("{{ .Metadata.LastTagTime }}")
    .arg(format!("serai-dev-{name}"))
    .output()
  {
    let last_tag_time_buf = String::from_utf8(res.stdout).expect("docker had non-utf8 output");
    let last_tag_time = last_tag_time_buf.trim();
    if !last_tag_time.is_empty() {
      let created_time = SystemTime::from(
        chrono::DateTime::parse_and_remainder(last_tag_time, "%F %T.%f %z")
          .unwrap_or_else(|_| {
            panic!("docker formatted last tag time unexpectedly: {last_tag_time}")
          })
          .0,
      );

      // For all services, if the Dockerfile was edited after the image was built we should rebuild
      let mut last_modified =
        fs::metadata(&dockerfile_path).ok().and_then(|meta| meta.modified().ok());

      // Check any additionally specified paths
      let meta = |path: PathBuf| (path.clone(), fs::metadata(path));
      let mut metadatas = match name.as_str() {
        "bitcoin" | "ethereum" | "monero" => vec![],
        "ethereum-relayer" => {
          vec![meta(repo_path.join("common")), meta(repo_path.join("networks"))]
        }
        "message-queue" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("substrate").join("primitives")),
          meta(repo_path.join("message-queue")),
        ],
        "bitcoin-processor" | "ethereum-processor" | "monero-processor" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("networks")),
          meta(repo_path.join("substrate")),
          meta(repo_path.join("message-queue")),
          meta(repo_path.join("processor")),
        ],
        "coordinator" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("networks")),
          meta(repo_path.join("substrate")),
          meta(repo_path.join("message-queue")),
          meta(repo_path.join("coordinator")),
        ],
        "runtime" | "serai" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("substrate")),
        ],
        _ => panic!("building unrecognized docker image"),
      };

      while !metadatas.is_empty() {
        if let (path, Ok(metadata)) = metadatas.pop().unwrap() {
          if metadata.is_file() {
            if let Ok(modified) = metadata.modified() {
              if modified >
                last_modified
                  .expect("got when source was last modified yet not when the Dockerfile was")
              {
                last_modified = Some(modified);
              }
            }
          } else {
            // Recursively crawl since we care when the folder's contents were edited, not the
            // folder itself
            for entry in fs::read_dir(path.clone()).expect("couldn't read directory") {
              metadatas.push(meta(
                path.join(entry.expect("couldn't access item in directory").file_name()),
              ));
            }
          }
        }
      }

      if let Some(last_modified) = last_modified {
        if last_modified < created_time {
          println!("{name} was built after the most recent source code edits, assuming built.");
          built_lock.insert(name, true);
          return;
        }
      }
    }
  }

  println!("Building {}...", &name);

  // Version which always prints
  if !Command::new("docker")
    .current_dir(&repo_path)
    .arg("build")
    .arg("-f")
    .arg(dockerfile_path)
    .arg(".")
    .arg("-t")
    .arg(format!("serai-dev-{name}"))
    .spawn()
    .unwrap()
    .wait()
    .unwrap()
    .success()
  {
    panic!("failed to build {name}");
  }

  // Version which only prints on error
  /*
  let res = Command::new("docker")
    .current_dir(dockerfile_path)
    .arg("build")
    .arg(".")
    .arg("-t")
    .arg(format!("serai-dev-{name}"))
    .output()
    .unwrap();
  if !res.status.success() {
    println!("failed to build {name}\n");
    println!("-- stdout --");
    println!(
      "{}\r\n",
      String::from_utf8(res.stdout)
        .unwrap_or_else(|_| "stdout had non-utf8 characters".to_string())
    );
    println!("-- stderr --");
    println!(
      "{}\r\n",
      String::from_utf8(res.stderr)
        .unwrap_or_else(|_| "stderr had non-utf8 characters".to_string())
    );
    panic!("failed to build {name}");
  }
  */

  println!("Built!");

  if std::env::var("GITHUB_CI").is_ok() {
    println!("In CI, so clearing cache to prevent hitting the storage limits.");
    if !Command::new("docker")
      .arg("builder")
      .arg("prune")
      .arg("--all")
      .arg("--force")
      .output()
      .unwrap()
      .status
      .success()
    {
      println!("failed to clear cache after building {name}\n");
    }
  }

  // Set built
  built_lock.insert(name, true);
}
