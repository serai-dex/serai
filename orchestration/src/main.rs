// TODO: Generate randomized RPC credentials for all services
// TODO: Generate keys for a validator and the infra

use core::ops::Deref;
use std::{env, path::PathBuf, io::Write, fs};

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

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
{additional_root}

# Switch to a non-root user
# System user (not a human), shell of nologin, no password assigned
RUN adduser -S -s /sbin/nologin -D {user}
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
{additional_root}

# Switch to a non-root user
RUN useradd --system --create-home --shell /sbin/nologin {user}
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
FROM rust:1.75-slim-bookworm as builder

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

fn dockerfiles(network: Network) {
  let orchestration_path = {
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
  };

  bitcoin(&orchestration_path, network);
  ethereum(&orchestration_path);
  monero(&orchestration_path, network);
  if network == Network::Dev {
    monero_wallet_rpc(&orchestration_path);
  }

  // Generate entropy for the infrastructure keys
  let mut entropy = [0; 32];
  OsRng.fill_bytes(&mut entropy);
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

  coordinator(&orchestration_path, network, coordinator_key.0);

  serai(&orchestration_path, network);
}

fn main() {
  dockerfiles(Network::Dev);
  dockerfiles(Network::Testnet);
}
