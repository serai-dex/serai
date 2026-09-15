use crate::Os;

const MIMALLOC_VERSION: &str = "636510a36ab743f76a582067142f29d15b024c90"; // 3.5.2
const HARDENING_FLAGS: &str = "-DMI_SECURE_FULL=ON -DMI_GUARDED=ON -DMI_XMALLOC=ON";
#[rustfmt::skip]
const COMPILATION_FLAGS: &str =
  "-DCMAKE_BUILD_TYPE=Release -DMI_OPT_ARCH=ON -DMI_OVERRIDE=ON -DMI_BUILD_SHARED=ON -DMI_BUILD_STATIC=OFF -DMI_BUILD_OBJECT=OFF -DMI_BUILD_TESTS=OFF";

pub fn mimalloc(os: Os, release: bool) -> String {
  let build_script = |env, additional_flags| {
    let flags = format!("{HARDENING_FLAGS} {COMPILATION_FLAGS} {additional_flags}");
    format!(
      r#"
RUN <<-'EOF'
  set -e

  git clone https://github.com/microsoft/mimalloc
  cd mimalloc
  git checkout {MIMALLOC_VERSION}

  # For some reason, `mimalloc` contains binary blobs in the repository, so we remove those now
  rm -rf .git ./bin

  mkdir -p out
  cd out

  export CFLAGS="$CFLAGS -O2 -fPIC -fstack-protector-strong -fstack-clash-protection"

  {env} cmake {flags} ..
  make

  cd ..

  # Copy the built library to the original directory
  cd ..
  cp mimalloc/out/libmimalloc-*.so ./libmimalloc.so
  # Clean up the source directory
  rm -rf ./mimalloc
EOF
  "#
    )
    // https://github.com/moby/buildkit/issues/4282
    .replace('\r', "")
  };

  let alpine_build = build_script("CC=$(uname -m)-alpine-linux-musl-gcc", "-DMI_LIBC_MUSL=ON");
  let debian_build = build_script("", if !release { "-DMI_TRACK_ASAN=ON" } else { "" });

  let alpine_mimalloc = format!(
    r#"
FROM alpine:latest AS mimalloc-alpine

RUN apk update && apk upgrade && apk --no-cache add musl-dev gcc make cmake git

{alpine_build}
"#
  );

  let debian_mimalloc = format!(
    r#"
FROM debian:stable-slim AS mimalloc-debian

RUN apt update && apt upgrade -y && apt install -y gcc make cmake git

{debian_build}
"#
  );

  match os {
    Os::Alpine => alpine_mimalloc,
    Os::Debian => debian_mimalloc,
  }
}
