// TODO: Generate randomized RPC credentials for all services
// TODO: Generate keys for a validator and the infra

use core::ops::Deref as _;
use std::{
  collections::{HashSet, HashMap},
  env,
  path::PathBuf,
  io::Write as _,
  fs,
  process::{Stdio, Command},
};

use zeroize::Zeroizing;

use rand_core::{RngCore as _, SeedableRng as _, OsRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript as _, RecommendedTranscript};

use dalek_ff_group::Ristretto;
use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField},
    GroupEncoding as _,
  },
  WrappedGroup,
};
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;

mod mimalloc;
use mimalloc::mimalloc;

mod networks;
use networks::*;

mod ethereum_relayer;
use ethereum_relayer::ethereum_relayer;

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
  zalloc::ZeroizingAlloc::wrap(std::alloc::System);

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

fn os(os: Os, release: bool, additional_root: &str, user: &str) -> String {
  match os {
    Os::Alpine => format!(
      r#"
FROM alpine:latest AS image

COPY --from=mimalloc-alpine libmimalloc.so /usr/lib
ENV LD_PRELOAD=libmimalloc.so

RUN apk update && apk upgrade

RUN adduser --system --shell /sbin/nologin --disabled-password {user}
RUN addgroup {user}
RUN addgroup {user} {user}

# Make the /volume directory and transfer it to the user
RUN mkdir /volume && chown {user}:{user} /volume

{additional_root}

# Switch to a non-root user
USER {user}

WORKDIR /home/{user}
"#
    ),

    Os::Debian => {
      let asan = if !release {
        /*
          `detect_stack_use_after_return` is on by default on some platforms, such as Linux (which
          this should qualify as), according to ASan's documentation. Rust notes it as a check to
          enable. We explicitly enable it to be sure it is on. While this incurs the risk of false
          positives, its usage within solely test environments makes this acceptable.
        */
        const ASAN_OPTS: &str = "ENV ASAN_OPTIONS=detect_stack_use_after_return=1";

        // `libasan` is dynamically linked, so we install it now
        // As we didn't explicitly link to it, we load it via `LD_PRELOAD`
        format!(
          r#"
RUN apt install -y libatomic1 libasan8
{ASAN_OPTS}
RUN echo "$(find /usr/lib -name libasan.so.8 | head -n1)" >> /etc/ld.so.preload
"#
        )
      } else {
        String::new()
      };
      format!(
        r#"
FROM debian:stable-slim AS image

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean

RUN useradd --system --user-group --create-home --shell /sbin/nologin {user}

# Make the /volume directory and transfer it to the user
RUN mkdir /volume && chown {user}:{user} /volume

{additional_root}

{asan}

COPY --from=mimalloc-debian libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

# Switch to a non-root user
USER {user}

WORKDIR /home/{user}
"#
      )
    }
  }
}

fn build_serai_service(
  prelude: &str,
  os: Os,
  release: bool,
  features: &str,
  package: &str,
) -> String {
  let profile = if release { "release" } else { "debug" };
  let profile_flag = if release { "--release" } else { "" };

  // We optimize for the current CPU since we aren't expected to generate portable containers
  let mut rustflags = "-C target-cpu=native -C opt-level=3".to_owned();

  /*
    We enable `-C stack-protector=all` (https://github.com/rust-lang/pull/146369) in its
    pre-stablized form. Per discussion on how to stablize it, we use `=all` as it's the option with
    well-defined semantics when considered within the context of Rust.
  */
  rustflags += " -Z stack-protector=all";

  /*
    TODO: Ideally, we would support CFI and even use it in production, but this seems to always
    report "illegal instruction" when ran. The following block is only here as if uncommented, it
    does compile and successfully produce a binary. It's solely that the binary doesn't work.

    https://github.com/serai-dex/serai/issues/737

  /*
    We enable LLVM's ControlFlowIntegrity, which requires enabling LTO.

    Some of the best-stated advocacy for this policy may be Android's documentation of it:
    https://source.android.com/docs/security/test/cfi
    The reasoning has the benefiting of connecting to the real-world impact while demonstrating
    this has been adopted, in production, by a major entity without notable issue or complaints (at
    least today, after the decade of time it's been since this hill was first climbed).

    `sanitizer=cfi` _requires_ `lto` or `linker-plugin-lto`, the latter not working out of the box.
    `lto` requires `embed-bitcode=yes` (changed from the default of `embed-bitcode=no`) _and_
    `codegen-units=1`.
  */
  rustflags += " -Z sanitizer=cfi -C lto -C embed-bitcode=yes -C codegen-units=1";
  */

  /*
    We want to enable LLVM's SafeStack sanitizer, which is recommended for usage even with
    production binaries. It only supports the `x86_64-unknown-linux-gnu` target however.

    We also want to enable LLVM's ASan as it's not expected to have false positives, errors upon
    detection (so we'll notice it even within CI-instrumented containers which shut down once the
    test is already considered to have passed), but it's only recommended for non-production
    use-cases. For `linux` targets, it only supports `linux-gnu` though and only for certain hosts.

    Unfortunately, these are incompatible, so we detect which are eligible in this environment and
    ensure we choose a valid (non-conflicting) configuration.

    This assumes the container architecture will equal the current host's architecture, as allowed
    by how this tool does not produce portable containers.
  */
  {
    let (safestack, asan) = {
      #[allow(unused)]
      let mut supports_safestack = false;
      #[cfg(target_arch = "x86_64")]
      {
        supports_safestack = os == Os::Debian;
      }

      #[allow(unused)]
      let mut supports_asan = false;
      #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
      {
        supports_asan = (!release) && (os == Os::Debian);
      }

      if supports_safestack && supports_asan {
        /*
          If both are supported, randomly choose one. This ensures both variants are tested with,
          despite how we only intend to use one in production (not leaving a gap where we don't
          test with SafeStack as desired in a production deployment).

          TODO: Instead of passing around `Network, Os`, design and develop a `Profile` system
          which consistently yields the configurations for all of these specific knobs. Right now,
          we frequently re-decide whether or not to enable ASan. We should also replace `bool` with
          `enum` for clarity.
        */
        supports_safestack = (OsRng.next_u64() & 1) == 1;
        supports_asan = !supports_safestack;
      }

      (supports_safestack, supports_asan)
    };
    if safestack {
      rustflags += " -Z sanitizer=safestack";
    } else if asan {
      /*
        We use the system's ASan runtime, not the one Rust will want to link in, due to
        instrumenting the allocator along with the Serai services themselves.

        This does dynamically link to _all_ sanitizer runtimes, but the only sanitizer we
        potentially use which requires a runtime is this one.
      */
      rustflags += " -Z sanitizer=address -Z external-clangrt -lasan";
    }
  }

  // x86(-64)-specific hardening
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  {
    /*
      Retpolines: https://support.google.com/faqs/answer/7625886

      These are tracked within `rustc` with: https://github.com/rust-lang/rust/issues/116852
    */
    rustflags += " -Z retpoline";
  }

  // AArch64-specific hardening.
  #[cfg(target_arch = "aarch64")]
  {
    /*
      Harden against straight-line speculation.

      https://github.com/rust-lang/rust/pull/136597 would allow us to specify `-Z harden-sls=all`
      and replace direct specification of these target features.
    */
    rustflags += " -C target-feature=+harden-sls-ijmp -C target-feature=+harden-sls-ret";

    /*
      Hardware-backed pointer authentication.

      `pac-ret,leaf` requires ARMv8.3-A to function, but are NOPs on older chips (so binaries
      remain portable).

      `bti` requires ARMv8.5-A, yet again is portable even to older chips.
    */
    rustflags += " -Z branch-protection=pac-ret,leaf,bti";

    // LLVM's MemTagSanitizer
    #[cfg(target_feature = "mte")]
    {
      rustflags += " -C target-feature=+mte -Z sanitizer=memtag";
    }
  }

  /*
    We explicitly enable debug assertions on debug, allowing us to independently tune the
    optimization level (as required for `serai-node`).

    We also enable `ub-checks`, considering them an extension of `debug-assertions`. While they
    produce aborting panics, which cannot be caught via unwinding, we do not make use of unwinding.

    When not compiling for production, we test randomized layouts. While ideally, we would enable
    this for security purposes (hardening), the feature is unstable and the risk of programmers who
    have assumed a layout is real. Instead of enabling it in a situation where we may have unsafe
    behavior, with critical effects, we solely enable it when debugging. This achieves its
    secondary purpose of helping to detect unsafe expectations about layouts.
  */
  if !release {
    rustflags += " -C debug-assertions=on -Z ub-checks=on -Z randomize-layout";
  }

  let image;
  (match os {
    Os::Debian => {
      image = "rust:slim-trixie";
      format!(
        r#"
FROM {image} AS builder

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean

# Add dev dependencies
RUN apt install -y libclang-dev clang

# Dependencies for the Serai node
RUN apt install -y protobuf-compiler

# Dependencies for `debug` builds
RUN apt install -y libasan8
"#
      )
    }
    Os::Alpine => {
      image = "rust:alpine";
      format!(
        r#"
FROM {image} AS builder

RUN apk update && apk upgrade

# Add dev dependencies
RUN apk add clang-dev
"#
      )
    }
  }) + &format!(
    r#"
{prelude}

# Add files for build
ADD patches /serai/patches
ADD common /serai/common
ADD crypto /serai/crypto
ADD networks /serai/networks
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD secret-store /serai/secret-store
ADD substrate /serai/substrate
ADD orchestration/Cargo.toml /serai/orchestration/Cargo.toml
ADD orchestration/src /serai/orchestration/src
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# `RUSTC_BOOTSTRAP` is required due to our use of nightly features
ENV RUSTC_BOOTSTRAP=1

RUN mkdir /serai/bin

# Mount the caches
RUN --mount=type=cache,from={image},source=/usr/local/rustup,target=/usr/local/rustup           \
  --mount=type=cache,from={image},source=/usr/local/cargo,target=/usr/local/cargo               \
  --mount=type=cache,target=/serai/target                                                       \
  <<EOF
  set -e

  # Add `rust-src` so we may compile the standard library with our desired configuration
  rustup component add rust-src

  # We require LTO, yet `rustc` doesn't understand LTO in `RUSTFLAGS` when a crate _may not_ be
  # compiled for the purposes of building an executable. To do this, we patch all our dependencies
  # to solely declare themselves as standard libraries via removing their `crate-type` entries.
  cargo fetch
  for path in $(find /usr/local/cargo -name "Cargo.toml"); do
    file=$(cat $path)
    if [ "$(grep "^crate-type" $path || true)" = "" ]; then continue; fi
    start=$(grep -n "^crate-type" $path | head -n1 | cut -f1 -d':')
    len=$(echo "$file" | tail -n+$start | grep -n "^\]$" | head -n1 | cut -f1 -d':')
    echo "$file" | head -n$(($start - 1)) > $path
    echo "$file" | tail -n+$(($start + len)) >> $path
  done

  # We disable `target-applies-to-host` due to Rust attempting weird `build-std`/sanitizer
  # configurations for build scripts otherwise.
  RUSTFLAGS="$RUSTFLAGS {rustflags}"                                                            \
  cargo build --locked                                                                          \
    -Z target-applies-to-host --config "target-applies-to-host=false"                           \
    -Z build-std=panic_abort,compiler_builtins,core,alloc,std,std_detect -Z build-std-features= \
    {profile_flag} --features "{features}" -p {package}

  # Copy out of the cached `target` directory to a stable location
  cp /serai/target/{profile}/{package} /serai/bin/
EOF
"#
  )
}

pub fn write_dockerfile(path: PathBuf, dockerfile: &str) {
  if let Ok(existing) = fs::read_to_string(&path).as_ref() &&
    (existing == dockerfile)
  {
    return;
  }

  let mut file = fs::File::create(path).unwrap();
  file.write_all("# syntax=docker/dockerfile:1\r\n".as_bytes()).unwrap();
  // We frequently use the legacy `CMD` syntax
  file.write_all("# check=skip=JSONArgsRecommended;error=true\r\n".as_bytes()).unwrap();
  file.write_all(dockerfile.as_bytes()).unwrap();
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

type InfrastructureKeys = HashMap<
  &'static str,
  (Zeroizing<<Ristretto as WrappedGroup>::F>, <Ristretto as WrappedGroup>::G),
>;
fn infrastructure_keys(network: Network) -> InfrastructureKeys {
  // Generate entropy for the infrastructure keys

  let entropy = if network == Network::Dev {
    // Don't use actual entropy if this is a dev environment
    Zeroizing::new([0; 32])
  } else {
    let path = home::home_dir()
      .unwrap()
      .join(".serai")
      .join(network.label())
      .join("infrastructure_keys_entropy");
    // Check if there's existing entropy
    if let Ok(entropy) = fs::read(&path).map(Zeroizing::new) {
      assert_eq!(entropy.len(), 32, "entropy saved to disk wasn't 32 bytes");
      let mut res = Zeroizing::new([0; 32]);
      res.copy_from_slice(entropy.as_ref());
      res
    } else {
      // If there isn't, generate fresh entropy
      let mut res = Zeroizing::new([0; 32]);
      OsRng.fill_bytes(res.as_mut());
      fs::write(&path, &res).unwrap();
      res
    }
  };

  let mut transcript =
    RecommendedTranscript::new(b"Serai Orchestrator Infrastructure Keys Transcript");
  transcript.append_message(b"network", network.label().as_bytes());
  transcript.append_message(b"entropy", entropy);
  let mut rng = ChaCha20Rng::from_seed(transcript.rng_seed(b"infrastructure_keys"));

  let mut key_pair = || {
    let key = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut rng));
    let public = Ristretto::generator() * key.deref();
    (key, public)
  };

  HashMap::from([
    ("coordinator", key_pair()),
    ("bitcoin", key_pair()),
    ("ethereum", key_pair()),
    ("monero", key_pair()),
  ])
}

struct EmbeddedCurveKeys {
  embedwards25519: (Zeroizing<Vec<u8>>, Vec<u8>),
  secq256k1: (Zeroizing<Vec<u8>>, Vec<u8>),
}

fn embedded_curve_keys(network: Network) -> EmbeddedCurveKeys {
  // Generate entropy for the embedded curve keys

  let entropy = {
    let path = home::home_dir()
      .unwrap()
      .join(".serai")
      .join(network.label())
      .join("embedded_curve_keys_entropy");
    // Check if there's existing entropy
    if let Ok(entropy) = fs::read(&path).map(Zeroizing::new) {
      assert_eq!(entropy.len(), 32, "entropy saved to disk wasn't 32 bytes");
      let mut res = Zeroizing::new([0; 32]);
      res.copy_from_slice(entropy.as_ref());
      res
    } else {
      // If there isn't, generate fresh entropy
      let mut res = Zeroizing::new([0; 32]);
      OsRng.fill_bytes(res.as_mut());
      fs::write(&path, &res).unwrap();
      res
    }
  };

  let mut transcript =
    RecommendedTranscript::new(b"Serai Orchestrator Embedded Curve Keys Transcript");
  transcript.append_message(b"network", network.label().as_bytes());
  transcript.append_message(b"entropy", entropy);
  let mut rng = ChaCha20Rng::from_seed(transcript.rng_seed(b"embedded_curve_keys"));

  EmbeddedCurveKeys {
    embedwards25519: {
      let key = Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut rng));
      let pub_key = Embedwards25519::generator() * key.deref();
      (Zeroizing::new(key.to_repr().as_ref().to_vec()), pub_key.to_bytes().to_vec())
    },
    secq256k1: {
      let key = Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut rng));
      let pub_key = Secq256k1::generator() * key.deref();
      (Zeroizing::new(key.to_repr().as_ref().to_vec()), pub_key.to_bytes().to_vec())
    },
  }
}

fn dockerfiles(network: Network) {
  let orchestration_path = orchestration_path(network);

  bitcoin(&orchestration_path, network);
  ethereum(&orchestration_path, network);
  monero(&orchestration_path, network);

  let mut infrastructure_keys = infrastructure_keys(network);
  let coordinator_key = infrastructure_keys.remove("coordinator").unwrap();
  let bitcoin_key = infrastructure_keys.remove("bitcoin").unwrap();
  let ethereum_key = infrastructure_keys.remove("ethereum").unwrap();
  let monero_key = infrastructure_keys.remove("monero").unwrap();

  ethereum_relayer(&orchestration_path, network);

  message_queue(
    &orchestration_path,
    network,
    coordinator_key.1,
    bitcoin_key.1,
    ethereum_key.1,
    monero_key.1,
  );

  let embedded_curve_keys = embedded_curve_keys(network);
  processor(
    &orchestration_path,
    network,
    "bitcoin",
    coordinator_key.1,
    bitcoin_key.0,
    embedded_curve_keys.embedwards25519.0.clone(),
    embedded_curve_keys.secq256k1.0.clone(),
  );
  processor(
    &orchestration_path,
    network,
    "ethereum",
    coordinator_key.1,
    ethereum_key.0,
    embedded_curve_keys.embedwards25519.0.clone(),
    embedded_curve_keys.secq256k1.0.clone(),
  );
  processor(
    &orchestration_path,
    network,
    "monero",
    coordinator_key.1,
    monero_key.0,
    embedded_curve_keys.embedwards25519.0.clone(),
    embedded_curve_keys.embedwards25519.0.clone(),
  );

  let serai_key = {
    let serai_key = Zeroizing::new(
      fs::read(home::home_dir().unwrap().join(".serai").join(network.label()).join("key"))
        .expect("couldn't read key for this network"),
    );
    let mut serai_key_repr =
      Zeroizing::new(<<Ristretto as WrappedGroup>::F as PrimeField>::Repr::default());
    serai_key_repr.as_mut().copy_from_slice(serai_key.as_ref());
    Zeroizing::new(<Ristretto as WrappedGroup>::F::from_repr(*serai_key_repr).unwrap())
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

  let key = <Ristretto as WrappedGroup>::F::random(&mut OsRng);

  let _ = fs::create_dir_all(&serai_dir);
  fs::write(key_file, key.to_repr()).expect("couldn't write key");

  // TODO: Move embedded curve key gen here, and print them
  println!(
    "Public Key: {}",
    hex::encode((<Ristretto as WrappedGroup>::generator() * key).to_bytes())
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
      "ethereum-relayer" => "ethereum-relayer",
      "message-queue" => "message-queue",
      "bitcoin-daemon" => "bitcoin",
      "bitcoin-processor" => "bitcoin-processor",
      "monero-daemon" => "monero",
      "monero-processor" => "monero-processor",
      _ => panic!("starting unrecognized service"),
    };

    // If we're building the Serai service, first build the runtime
    let serai_runtime_volume = format!("serai-{}-runtime-volume", network.label());
    if name == "serai" {
      // Check if it's built by checking if the volume has the expected runtime file
      let wasm_build_container_name = format!("serai-{}-runtime", network.label());
      let built = || {
        if let Ok(state_and_status) = Command::new("docker")
          .arg("inspect")
          .arg("-f")
          .arg("{{.State.Status}}:{{.State.ExitCode}}")
          .arg(&wasm_build_container_name)
          .output() &&
          let Ok(state_and_status) = String::from_utf8(state_and_status.stdout)
        {
          return state_and_status.trim() == "exited:0";
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
          .arg("--no-cache")
          .arg("--file=./orchestration/runtime/Containerfile")
          .arg("--tag")
          .arg(format!("serai-{}-runtime-img", network.label()))
          .arg(".")
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
          .arg("--pull")
          .arg("never")
          .arg("--name")
          .arg(container_name)
          .arg("--volume")
          .arg(format!("{serai_runtime_volume}:/volume"))
          .arg(format!("serai-{}-runtime-img", network.label()))
          .spawn();

        // Wait until its built
        let mut ticks = 0;
        while !built() {
          std::thread::sleep(core::time::Duration::from_mins(1));
          ticks += 1;
          assert!(ticks < (24 * 60), "couldn't build the runtime after 24 hours");
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
          if network == Network::Dev { command.arg("-p").arg("8332:8332") } else { command }
        }
        "ethereum-relayer" => {
          // Expose the router command fetch server
          command.arg("-p").arg("20831:20831")
        }
        "monero" => {
          // Expose the RPC for tests
          if network == Network::Dev { command.arg("-p").arg("18081:18081") } else { command }
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
    Generate a key for the validator.

  setup *network*
    Generate the Dockerfiles for every Serai service.

  start *network* [service1, service2...]
    Start the specified services for the specified network ("dev" or "testnet").

    - `serai`
    - `coordinator`
    - `message-queue`
    - `bitcoin-daemon`
    - `bitcoin-processor`
    - `ethereum-daemon`
    - `ethereum-processor`
    - `ethereum-relayer`
    - `monero-daemon`
    - `monero-processor`

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
        if arg == "ethereum-processor" {
          services.insert("ethereum-relayer".to_owned());
        }
        if let Some(ext_network) = arg.strip_suffix("-processor") {
          services.insert(ext_network.to_owned() + "-daemon");
        }
        services.insert(arg);
      }

      start(network, services);
    }
    _ => help(),
  }
}
