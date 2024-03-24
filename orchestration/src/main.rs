// TODO: Generate randomized RPC credentials for all services
// TODO: Generate keys for a validator and the infra

use core::ops::Deref;
use std::{
  collections::HashSet,
  env,
  path::PathBuf,
  io::Write,
  fs,
  process::{Stdio, Command},
};

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    GroupEncoding,
  },
  Ciphersuite, Ristretto,
};

mod mimalloc;
use mimalloc::mimalloc;

mod coins;
use coins::*;

mod message_queue;
use message_queue::message_queue;

mod processor;
use processor::processor;

mod coordinator;
use coordinator::coordinator;

mod serai;
use serai::serai;

mod docker;

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Network {
  Dev,
  Testnet,
}

impl Network {
  pub fn db(&self) -> &'static str {
    match self {
      Network::Dev => "parity-db",
      Network::Testnet => "rocksdb",
    }
  }

  pub fn release(&self) -> bool {
    match self {
      Network::Dev => false,
      Network::Testnet => true,
    }
  }

  pub fn label(&self) -> &'static str {
    match self {
      Network::Dev => "dev",
      Network::Testnet => "testnet",
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
enum Os {
  Alpine,
  Debian,
}

fn os(os: Os, additional_root: &str, user: &str) -> String {
  match os {
    Os::Alpine => format!(
      r#"
FROM alpine:latest as image

COPY --from=mimalloc-alpine libmimalloc.so /usr/lib
ENV LD_PRELOAD=libmimalloc.so

RUN apk update && apk upgrade

# System user (not a human), shell of nologin, no password assigned
RUN adduser -S -s /sbin/nologin -D {user}

# Make the /volume directory and transfer it to the user
RUN mkdir /volume && chown {user}:{user} /volume

{additional_root}

# Switch to a non-root user
USER {user}

WORKDIR /home/{user}
"#
    ),

    Os::Debian => format!(
      r#"
FROM debian:bookworm-slim as image

COPY --from=mimalloc-debian libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean

RUN useradd --system --create-home --shell /sbin/nologin {user}

# Make the /volume directory and transfer it to the user
RUN mkdir /volume && chown {user}:{user} /volume

{additional_root}

# Switch to a non-root user
USER {user}

WORKDIR /home/{user}
"#
    ),
  }
}

fn build_serai_service(release: bool, features: &str, package: &str) -> String {
  let profile = if release { "release" } else { "debug" };
  let profile_flag = if release { "--release" } else { "" };

  format!(
    r#"
FROM rust:1.77-slim-bookworm as builder

COPY --from=mimalloc-debian libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean

# Add dev dependencies
RUN apt install -y pkg-config clang

# Dependencies for the Serai node
RUN apt install -y make protobuf-compiler

# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

# Add files for build
ADD patches /serai/patches
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD substrate /serai/substrate
ADD orchestration/Cargo.toml /serai/orchestration/Cargo.toml
ADD orchestration/src /serai/orchestration/src
ADD mini /serai/mini
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/serai/target \
  mkdir /serai/bin && \
  cargo build {profile_flag} --features "{features}" -p {package} && \
  mv /serai/target/{profile}/{package} /serai/bin
"#
  )
}

pub fn write_dockerfile(path: PathBuf, dockerfile: &str) {
  if let Ok(existing) = fs::read_to_string(&path).as_ref() {
    if existing == dockerfile {
      return;
    }
  }
  fs::File::create(path).unwrap().write_all(dockerfile.as_bytes()).unwrap();
}

fn orchestration_path(network: Network) -> PathBuf {
  let mut repo_path = env::current_exe().unwrap();
  repo_path.pop();
  assert!(repo_path.as_path().ends_with("debug"));
  repo_path.pop();
  assert!(repo_path.as_path().ends_with("target"));
  repo_path.pop();

  let mut orchestration_path = repo_path.clone();
  orchestration_path.push("orchestration");
  orchestration_path.push(network.label());
  orchestration_path
}

fn dockerfiles(network: Network) {
  let orchestration_path = orchestration_path(network);

  bitcoin(&orchestration_path, network);
  ethereum(&orchestration_path);
  monero(&orchestration_path, network);
  if network == Network::Dev {
    monero_wallet_rpc(&orchestration_path);
  }

  // TODO: Generate infra keys in key_gen, yet service entropy here?

  // Generate entropy for the infrastructure keys
  let mut entropy = Zeroizing::new([0; 32]);
  // Only use actual entropy if this isn't a development environment
  if network != Network::Dev {
    OsRng.fill_bytes(entropy.as_mut());
  }
  let mut transcript = RecommendedTranscript::new(b"Serai Orchestrator Transcript");
  transcript.append_message(b"entropy", entropy);
  let mut new_rng = |label| ChaCha20Rng::from_seed(transcript.rng_seed(label));

  let mut message_queue_keys_rng = new_rng(b"message_queue_keys");
  let mut key_pair = || {
    let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut message_queue_keys_rng));
    let public = Ristretto::generator() * key.deref();
    (key, public)
  };
  let coordinator_key = key_pair();
  let bitcoin_key = key_pair();
  let ethereum_key = key_pair();
  let monero_key = key_pair();

  message_queue(
    &orchestration_path,
    network,
    coordinator_key.1,
    bitcoin_key.1,
    ethereum_key.1,
    monero_key.1,
  );

  let mut processor_entropy_rng = new_rng(b"processor_entropy");
  let mut new_entropy = || {
    let mut res = Zeroizing::new([0; 32]);
    processor_entropy_rng.fill_bytes(res.as_mut());
    res
  };
  processor(
    &orchestration_path,
    network,
    "bitcoin",
    coordinator_key.1,
    bitcoin_key.0,
    new_entropy(),
  );
  processor(
    &orchestration_path,
    network,
    "ethereum",
    coordinator_key.1,
    ethereum_key.0,
    new_entropy(),
  );
  processor(&orchestration_path, network, "monero", coordinator_key.1, monero_key.0, new_entropy());

  let serai_key = {
    let serai_key = Zeroizing::new(
      fs::read(home::home_dir().unwrap().join(".serai").join(network.label()).join("key"))
        .expect("couldn't read key for this network"),
    );
    let mut serai_key_repr =
      Zeroizing::new(<<Ristretto as Ciphersuite>::F as PrimeField>::Repr::default());
    serai_key_repr.as_mut().copy_from_slice(serai_key.as_ref());
    Zeroizing::new(<Ristretto as Ciphersuite>::F::from_repr(*serai_key_repr).unwrap())
  };

  coordinator(&orchestration_path, network, coordinator_key.0, &serai_key);

  serai(&orchestration_path, network, &serai_key);
}

fn key_gen(network: Network) {
  let serai_dir = home::home_dir().unwrap().join(".serai").join(network.label());
  let key_file = serai_dir.join("key");
  if fs::File::open(&key_file).is_ok() {
    println!("already created key");
    return;
  }

  let key = <Ristretto as Ciphersuite>::F::random(&mut OsRng);

  let _ = fs::create_dir_all(&serai_dir);
  fs::write(key_file, key.to_repr()).expect("couldn't write key");

  println!(
    "Public Key: {}",
    hex::encode((<Ristretto as Ciphersuite>::generator() * key).to_bytes())
  );
}

fn start(network: Network, services: HashSet<String>) {
  // Create the serai network
  Command::new("docker")
    .arg("network")
    .arg("create")
    .arg("--driver")
    .arg("bridge")
    .arg("serai")
    .output()
    .unwrap();

  for service in services {
    println!("Starting {service}");
    let name = match service.as_ref() {
      "serai" => "serai",
      "coordinator" => "coordinator",
      "message-queue" => "message-queue",
      "bitcoin-daemon" => "bitcoin",
      "bitcoin-processor" => "bitcoin-processor",
      "monero-daemon" => "monero",
      "monero-processor" => "monero-processor",
      "monero-wallet-rpc" => "monero-wallet-rpc",
      _ => panic!("starting unrecognized service"),
    };

    // If we're building the Serai service, first build the runtime
    let serai_runtime_volume = format!("serai-{}-runtime-volume", network.label());
    if name == "serai" {
      // Check if it's built by checking if the volume has the expected runtime file
      let built = || {
        if let Ok(path) = Command::new("docker")
          .arg("volume")
          .arg("inspect")
          .arg("-f")
          .arg("{{ .Mountpoint }}")
          .arg(&serai_runtime_volume)
          .output()
        {
          if let Ok(path) = String::from_utf8(path.stdout) {
            if let Ok(iter) = std::fs::read_dir(PathBuf::from(path.trim())) {
              for item in iter.flatten() {
                if item.file_name() == "serai.wasm" {
                  return true;
                }
              }
            }
          }
        }
        false
      };

      if !built() {
        let mut repo_path = env::current_exe().unwrap();
        repo_path.pop();
        if repo_path.as_path().ends_with("deps") {
          repo_path.pop();
        }
        assert!(repo_path.as_path().ends_with("debug") || repo_path.as_path().ends_with("release"));
        repo_path.pop();
        assert!(repo_path.as_path().ends_with("target"));
        repo_path.pop();

        // Build the image to build the runtime
        if !Command::new("docker")
          .current_dir(&repo_path)
          .arg("build")
          .arg("-f")
          .arg("orchestration/runtime/Dockerfile")
          .arg(".")
          .arg("-t")
          .arg(format!("serai-{}-runtime-img", network.label()))
          .spawn()
          .unwrap()
          .wait()
          .unwrap()
          .success()
        {
          panic!("failed to build runtime image");
        }

        // Run the image, building the runtime
        println!("Building the Serai runtime");
        let container_name = format!("serai-{}-runtime", network.label());
        let _ =
          Command::new("docker").arg("rm").arg("-f").arg(&container_name).spawn().unwrap().wait();
        let _ = Command::new("docker")
          .arg("run")
          .arg("--name")
          .arg(container_name)
          .arg("--volume")
          .arg(format!("{serai_runtime_volume}:/volume"))
          .arg(format!("serai-{}-runtime-img", network.label()))
          .spawn();

        // Wait until its built
        let mut ticks = 0;
        while !built() {
          std::thread::sleep(core::time::Duration::from_secs(60));
          ticks += 1;
          if ticks > 6 * 60 {
            panic!("couldn't build the runtime after 6 hours")
          }
        }
      }
    }

    // Build it
    println!("Building {service}");
    docker::build(&orchestration_path(network), network, name);

    let docker_name = format!("serai-{}-{name}", network.label());
    let docker_image = format!("{docker_name}-img");
    if !Command::new("docker")
      .arg("container")
      .arg("inspect")
      .arg(&docker_name)
      // Use null for all IO to silence 'container does not exist'
      .stdin(Stdio::null())
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .unwrap()
      .success()
    {
      // Create the docker container
      println!("Creating new container for {service}");
      let volume = format!("serai-{}-{name}-volume:/volume", network.label());
      let mut command = Command::new("docker");
      let command = command.arg("create").arg("--name").arg(&docker_name);
      let command = command.arg("--network").arg("serai");
      let command = command.arg("--restart").arg("always");
      let command = command.arg("--log-opt").arg("max-size=100m");
      let command = command.arg("--log-opt").arg("max-file=3");
      let command = if network == Network::Dev {
        command
      } else {
        // Assign a persistent volume if this isn't for Dev
        command.arg("--volume").arg(volume)
      };
      let command = match name {
        "bitcoin" => {
          // Expose the RPC for tests
          if network == Network::Dev {
            command.arg("-p").arg("8332:8332")
          } else {
            command
          }
        }
        "monero" => {
          // Expose the RPC for tests
          if network == Network::Dev {
            command.arg("-p").arg("18081:18081")
          } else {
            command
          }
        }
        "monero-wallet-rpc" => {
          assert_eq!(network, Network::Dev, "monero-wallet-rpc is only for dev");
          // Expose the RPC for tests
          command.arg("-p").arg("18082:18082")
        }
        "coordinator" => {
          if network == Network::Dev {
            command
          } else {
            // Publish the port
            command.arg("-p").arg("30563:30563")
          }
        }
        "serai" => {
          let command = command.arg("--volume").arg(format!("{serai_runtime_volume}:/runtime"));
          if network == Network::Dev {
            command
          } else {
            // Publish the port
            command.arg("-p").arg("30333:30333")
          }
        }
        _ => command,
      };
      assert!(
        command.arg(docker_image).status().unwrap().success(),
        "couldn't create the container"
      );
    }

    // Start it
    // TODO: Check it successfully started
    println!("Starting existing container for {service}");
    let _ = Command::new("docker").arg("start").arg(docker_name).output();
  }
}

fn main() {
  let help = || -> ! {
    println!(
      r#"
Serai Orchestrator v0.0.1

Commands:
  key_gen *network*
    Generates a key for the validator.

  setup *network*
    Generate infrastructure keys and the Dockerfiles for every Serai service.

  start *network* [service1, service2...]
    Start the specified services for the specified network ("dev" or "testnet").

    - `serai`
    - `coordinator`
    - `message-queue`
    - `bitcoin-daemon`
    - `bitcoin-processor`
    - `monero-daemon`
    - `monero-processor`
    - `monero-wallet-rpc` (if "dev")

    are valid services.

    `*network*-processor` will automatically start `*network*-daemon`.
"#
    );
    std::process::exit(1);
  };

  let mut args = env::args();
  args.next();
  let command = args.next();
  let network = match args.next().as_ref().map(AsRef::as_ref) {
    Some("dev") => Network::Dev,
    Some("testnet") => Network::Testnet,
    Some(_) => panic!(r#"unrecognized network. only "dev" and "testnet" are recognized"#),
    None => help(),
  };

  match command.as_ref().map(AsRef::as_ref) {
    Some("key_gen") => {
      key_gen(network);
    }
    Some("setup") => {
      dockerfiles(network);
    }
    Some("start") => {
      let mut services = HashSet::new();
      for arg in args {
        if let Some(ext_network) = arg.strip_suffix("-processor") {
          services.insert(ext_network.to_string() + "-daemon");
        }
        services.insert(arg);
      }

      start(network, services);
    }
    _ => help(),
  }
}
