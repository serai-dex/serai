use std::{
  sync::{OnceLock, Arc},
  collections::{HashSet, HashMap},
  time::SystemTime,
  path::PathBuf,
  fs, env,
};

use tokio::{sync::Mutex, process::Command};

static BUILT: OnceLock<Mutex<HashMap<String, Arc<Mutex<bool>>>>> = OnceLock::new();
async fn build_inner(name: String) {
  let built = BUILT.get_or_init(|| Mutex::new(HashMap::new()));
  // Only one call to build will acquire this lock
  let mut built_lock = built.lock().await;
  if !built_lock.contains_key(&name) {
    built_lock.insert(name.clone(), Arc::new(Mutex::new(false)));
  }
  let this_lock = built_lock[&name].clone();
  drop(built_lock);

  let mut built_lock = this_lock.lock().await;
  // Already built
  if *built_lock {
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

  let mut orchestration_path = repo_path.clone();
  orchestration_path.push("orchestration");

  let name_without_serai_dev = name.split("serai-dev-").nth(1).unwrap_or(&name);

  // If this Docker image was created after this repo was last edited, return here
  // This should have better performance than Docker and allows running while offline
  if let Ok(res) = Command::new("docker")
    .arg("inspect")
    .arg("-f")
    .arg("{{ .Metadata.LastTagTime }}")
    .arg(name.clone())
    .output()
    .await
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

      let mut dockerfile_path = orchestration_path.clone();
      {
        let name = name_without_serai_dev;
        if HashSet::from(["bitcoin", "ethereum", "monero"]).contains(&name) {
          dockerfile_path = dockerfile_path.join("coins");
        }
        if name.contains("-processor") {
          dockerfile_path = dockerfile_path
            .join("processor")
            .join(name.split('-').next().unwrap())
            .join("Dockerfile");
        } else {
          dockerfile_path = dockerfile_path.join(name).join("Dockerfile");
        }
      }

      // For all services, if the Dockerfile was edited after the image was built we should rebuild
      let mut last_modified =
        fs::metadata(dockerfile_path).ok().and_then(|meta| meta.modified().ok());

      // Check any additionally specified paths
      let meta = |path: PathBuf| (path.clone(), fs::metadata(path));
      let mut metadatas = match name_without_serai_dev {
        "bitcoin" => vec![],
        "monero" => vec![],
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
        "runtime" => vec![
          meta(repo_path.join("common")),
          meta(repo_path.join("crypto")),
          meta(repo_path.join("substrate")),
        ],
        "serai" => vec![
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
          println!("{} was built after the most recent source code edits, assuming built.", name);
          *built_lock = true;
          return;
        }
      }
    }
  }

  println!("Building {}...", &name);

  // Version which always prints
  /*
  if !Command::new("docker")
    .current_dir(orchestration_path)
    .arg("compose")
    .arg("build")
    .arg(&name)
    .spawn()
    .unwrap()
    .wait()
    .await
    .unwrap()
    .success()
  {
    panic!("failed to build {name}");
  }
  */

  // Version which only prints on error
  let res = Command::new("docker")
    .current_dir(orchestration_path)
    .arg("compose")
    .arg("build")
    .arg(name_without_serai_dev)
    .output()
    .await
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

  println!("Built!");

  // Set built
  *built_lock = true;
}

async fn clear_cache_if_github() {
  if std::env::var("GITHUB_CI").is_ok() {
    println!("In CI, so clearing cache to prevent hitting the storage limits.");
    if !Command::new("docker")
      .arg("builder")
      .arg("prune")
      .arg("--all")
      .arg("--force")
      .output()
      .await
      .unwrap()
      .status
      .success()
    {
      println!("failed to clear cache\n");
    }
  }
}

pub async fn build(name: String) {
  build_inner(name).await;
  clear_cache_if_github().await;
}

pub async fn build_batch(names: Vec<String>) {
  let mut handles = vec![];
  for name in names.into_iter().collect::<HashSet<_>>() {
    handles.push(tokio::spawn(build_inner(name)));
  }
  for handle in handles {
    handle.await.unwrap();
  }
  clear_cache_if_github().await;
}
