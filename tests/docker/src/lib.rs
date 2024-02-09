use std::{
  sync::{Mutex, OnceLock},
  collections::{HashSet, HashMap},
  time::SystemTime,
  path::PathBuf,
  fs, env,
  process::Command,
};

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

// TODO: Merge this with what's in serai-orchestrator/have serai-orchestrator perform building
static BUILT: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
pub fn build(name: String) {
  let built = BUILT.get_or_init(|| Mutex::new(HashMap::new()));
  // Only one call to build will acquire this lock
  let mut built_lock = built.lock().unwrap();
  if built_lock.contains_key(&name) {
    // If it was built, return
    return;
  }

  // Else, hold the lock while we build
  let mut repo_path = env::current_exe().unwrap();
  repo_path.pop();
  assert!(repo_path.as_path().ends_with("deps"));
  repo_path.pop();
  assert!(repo_path.as_path().ends_with("debug"));
  repo_path.pop();
  assert!(repo_path.as_path().ends_with("target"));
  repo_path.pop();

  // Run the orchestrator to ensure the most recent files exist
  if !Command::new("cargo")
    .current_dir(&repo_path)
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
    .current_dir(&repo_path)
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

  let mut orchestration_path = repo_path.clone();
  orchestration_path.push("orchestration");
  if name != "runtime" {
    orchestration_path.push("dev");
  }

  let mut dockerfile_path = orchestration_path.clone();
  if HashSet::from(["bitcoin", "ethereum", "monero"]).contains(name.as_str()) {
    dockerfile_path = dockerfile_path.join("coins");
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
        "bitcoin" | "monero" => vec![],
        "message-queue" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("substrate").join("primitives")),
          meta(repo_path.join("message-queue")),
        ],
        "bitcoin-processor" | "ethereum-processor" | "monero-processor" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("coins")),
          meta(repo_path.join("substrate")),
          meta(repo_path.join("message-queue")),
          meta(repo_path.join("processor")),
        ],
        "coordinator" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("coins")),
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
