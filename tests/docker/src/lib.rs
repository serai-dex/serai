use std::{
  sync::{Mutex, OnceLock},
  collections::HashMap,
  env,
};

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
  let mut path = env::current_exe().unwrap();
  path.pop();
  assert!(path.as_path().ends_with("deps"));
  path.pop();
  assert!(path.as_path().ends_with("debug"));
  path.pop();
  assert!(path.as_path().ends_with("target"));
  path.pop();
  path.push("deploy");

  println!("Building {}...", &name);

  assert!(std::process::Command::new("docker")
    .current_dir(path)
    .arg("compose")
    .arg("build")
    .arg(&name)
    .spawn()
    .unwrap()
    .wait()
    .unwrap()
    .success());

  println!("Built!");

  // Set built
  built_lock.insert(name, true);
}
