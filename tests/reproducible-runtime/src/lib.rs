#[test]
pub fn reproducibly_builds() {
  use std::{collections::HashSet, process::Command};

  use rand_core::{RngCore, OsRng};

  use dockertest::{PullPolicy, Image, TestBodySpecification, DockerTest};

  const RUNS: usize = 3;
  const TIMEOUT: u16 = 180 * 60; // 3 hours

  serai_docker_tests::build("runtime".to_string());

  let mut ids = vec![[0; 8]; RUNS];
  for id in &mut ids {
    OsRng.fill_bytes(id);
  }

  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  for id in &ids {
    test.provide_container(
      TestBodySpecification::with_image(
        Image::with_repository("serai-dev-runtime").pull_policy(PullPolicy::Never),
      )
      .set_handle(format!("runtime-build-{}", hex::encode(id)))
      .replace_cmd(vec![
        "sh".to_string(),
        "-c".to_string(),
        // Sleep for a minute after building to prevent the container from closing before we
        // retrieve the hash
        "cd /serai/substrate/runtime && cargo clean && cargo build --release &&
           printf \"Runtime hash: \" > hash &&
           sha256sum /serai/target/release/wbuild/serai-runtime/serai_runtime.wasm >> hash &&
           cat hash &&
           sleep 60"
          .to_string(),
      ]),
    );
  }

  test.run(|_| async {
    let ids = ids;
    let mut containers = vec![];
    for container in String::from_utf8(
      Command::new("docker").arg("ps").arg("--format").arg("{{.Names}}").output().unwrap().stdout,
    )
    .expect("output wasn't utf-8")
    .lines()
    {
      for id in &ids {
        if container.contains(&hex::encode(id)) {
          containers.push(container.trim().to_string());
        }
      }
    }
    assert_eq!(containers.len(), RUNS, "couldn't find all containers");

    let mut res = vec![None; RUNS];
    'attempt: for _ in 0 .. (TIMEOUT / 10) {
      tokio::time::sleep(core::time::Duration::from_secs(10)).await;

      'runner: for (i, container) in containers.iter().enumerate() {
        if res[i].is_some() {
          continue;
        }

        let logs = Command::new("docker").arg("logs").arg(container).output().unwrap();
        let Some(last_log) =
          std::str::from_utf8(&logs.stdout).expect("output wasn't utf-8").lines().last()
        else {
          continue 'runner;
        };

        let split = last_log.split("Runtime hash: ").collect::<Vec<_>>();
        if split.len() == 2 {
          res[i] = Some(split[1].to_string());
          continue 'runner;
        }
      }

      for item in &res {
        if item.is_none() {
          continue 'attempt;
        }
      }
      break;
    }

    // If we didn't get results from all runners, panic
    for item in &res {
      if item.is_none() {
        panic!("couldn't get runtime hashes within allowed time");
      }
    }
    let mut identical = HashSet::new();
    for res in res.clone() {
      identical.insert(res.unwrap());
    }
    assert_eq!(identical.len(), 1, "got different runtime hashes {:?}", res);
  });
}
