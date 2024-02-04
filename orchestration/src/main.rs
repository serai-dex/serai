// TODO: Differentiate development/testnet/mainnet (including parity-db usage)

use std::{env, path::PathBuf, io::Write, fs};

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

pub fn write_dockerfile(path: PathBuf, dockerfile: &str) {
  if let Ok(existing) = fs::read_to_string(&path).as_ref() {
    if existing == dockerfile {
      return;
    }
  }
  fs::File::create(path).unwrap().write_all(dockerfile.as_bytes()).unwrap();
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
enum Os {
  Alpine,
  Debian,
}

#[rustfmt::skip]
fn os(os: Os, additional_root: &str, user: &str) -> String {
  match os {
    Os::Alpine => format!(r#"
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
"#),

    Os::Debian => format!(r#"
FROM debian:bookworm-slim as image

COPY --from=mimalloc-debian libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean
{additional_root}

# Switch to a non-root user
RUN useradd --system --create-home --shell /sbin/nologin {user}
USER {user}

WORKDIR /home/{user}
"#),
  }
}

#[rustfmt::skip]
fn build_serai_service(release: bool, features: &str, package: &str) -> String {
  let profile = if release { "release" } else { "debug" };

  format!(r#"
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
ADD orchestration /serai/orchestration
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
  cargo build --{profile} --features "{features}" -p {package} && \
  mv /serai/target/{profile}/{package} /serai/bin
"#)
}

fn main() {
  let orchestration_path = {
    let mut repo_path = env::current_exe().unwrap();
    repo_path.pop();
    assert!(repo_path.as_path().ends_with("debug"));
    repo_path.pop();
    assert!(repo_path.as_path().ends_with("target"));
    repo_path.pop();

    let mut orchestration_path = repo_path.clone();
    orchestration_path.push("orchestration");
    orchestration_path
  };

  bitcoin(&orchestration_path);
  ethereum(&orchestration_path);
  monero(&orchestration_path);
  monero_wallet_rpc(&orchestration_path);

  message_queue(&orchestration_path);

  processor(&orchestration_path, "bitcoin");
  processor(&orchestration_path, "ethereum");
  processor(&orchestration_path, "monero");

  coordinator(&orchestration_path);

  serai(&orchestration_path);
}
