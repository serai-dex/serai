use crate::Os;

// 3.3.2
const MIMALLOC_VERSION: &str = "30b2d9d89099bee08e9f67a1ffb3e12e7ba45227";
const HARDENING_FLAGS: &str = "-DMI_SECURE_FULL=ON -DMI_GUARDED=ON -DMI_XMALLOC=ON";
#[rustfmt::skip]
const COMPILATION_FLAGS: &str =
  "-DMI_OVERRIDE=ON -DMI_OPT_ARCH=ON -DMI_BUILD_SHARED=ON -DMI_BUILD_STATIC=OFF -DMI_BUILD_OBJECT=OFF -DMI_BUILD_TESTS=OFF";

pub fn mimalloc(os: Os, release: bool) -> String {
  let build_script = |env, additional_flags| {
    let flags = format!("{HARDENING_FLAGS} {COMPILATION_FLAGS} {additional_flags}");
    format!(
      r#"
#!/bin/sh
set -e

git clone https://github.com/microsoft/mimalloc
cd mimalloc
git checkout {MIMALLOC_VERSION}

# For some reason, `mimalloc` contains binary blobs in the repository, so we remove those now
rm -rf .git ./bin

mkdir -p out
cd out

{env} cmake {flags} ..
make

cd ..

# Copy the built library to the original directory
cd ..
cp mimalloc/out/libmimalloc-*.so ./libmimalloc.so
# Clean up the source directory
rm -rf ./mimalloc
  "#
    )
  };

  let build_commands = |env, additional_flags| {
    let mut result = String::new();
    for line in build_script(env, additional_flags)
      .lines()
      .map(|line| {
        assert!(!line.contains('"'));
        format!(r#"RUN echo "{line}" >> ./mimalloc.sh"#)
      })
      .chain(["RUN /bin/sh ./mimalloc.sh", "RUN rm ./mimalloc.sh"].into_iter().map(str::to_owned))
    {
      result.push_str(&line);
      result.push('\n');
    }
    result
  };
  let alpine_build = build_commands("CC=$(uname -m)-alpine-linux-musl-gcc", "-DMI_LIBC_MUSL=ON");
  let debian_build = build_commands("", if !release { "-DMI_TRACK_ASAN=ON" } else { "" });

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
