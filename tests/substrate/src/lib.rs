use std::time::Duration;

use serai_client_serai::Serai;

use dockertest::{StartPolicy, PullPolicy, Image, TestBodySpecification, DockerOperations};

pub struct Handle(String);

pub fn composition(name: &str, logs_path: String) -> (TestBodySpecification, Handle) {
  let handle = serai_docker_tests::handle(&format!("serai-{name}"));
  serai_docker_tests::build("serai".to_string());
  (
    TestBodySpecification::with_image(
      Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
    )
    .replace_env(
      [("SERAI_NAME".to_string(), name.to_lowercase()), ("KEY".to_string(), " ".to_string())]
        .into(),
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

  // If the RPC server has yet to start, sleep for up to 5 minutes until it does
  let client = Serai::new(serai_rpc.clone()).unwrap();
  for _ in 0 .. 300 {
    tokio::time::sleep(Duration::from_secs(1)).await;
    if client.block_by_number(0).await.is_err() {
      continue;
    }
    return client;
  }
  panic!("serai RPC server wasn't available after 5 minutes");
}
