use core::time::Duration;

use serai_client_serai::Serai;

use dockertest::{StartPolicy, PullPolicy, Image, TestBodySpecification, DockerOperations};

pub struct Handle(String);

pub fn composition(name: &str, logs_path: String) -> (TestBodySpecification, Handle) {
  let handle = serai_docker_tests::handle(&format!("serai-{name}"));
  serai_docker_tests::build("serai".to_owned());
  (
    TestBodySpecification::with_image(
      Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
    )
    .replace_env(
      [("SERAI_NAME".to_owned(), name.to_lowercase()), ("KEY".to_owned(), " ".to_owned())].into(),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_publish_all_ports(true)
    .set_handle(handle.clone())
    .set_log_options(Some(serai_docker_tests::log_options(logs_path))),
    Handle(handle),
  )
}

pub async fn rpc(ops: &DockerOperations, handle: Handle) -> Serai {
  let serai_rpc = ops.handle(&handle.0).host_port(9944).unwrap();
  let serai_rpc = format!("http://{}:{}", serai_rpc.0, serai_rpc.1);

  // Substrate takes a while to boot, especially with `--profile debug`, especially in CI
  #[expect(unexpected_cfgs)]
  const MINUTES: u64 = {
    #[cfg(github_ci)]
    let res = 20;
    #[cfg(not(github_ci))]
    let res = 10;
    res
  };

  let start = std::time::Instant::now();
  let client = Serai::new(serai_rpc.clone()).unwrap();
  while start.elapsed() < Duration::from_mins(MINUTES) {
    tokio::time::sleep(Duration::from_secs(1)).await;
    if client.block_by_number(0).await.is_err() {
      continue;
    }
    return client;
  }
  panic!("serai RPC server wasn't available after {MINUTES} minutes");
}
