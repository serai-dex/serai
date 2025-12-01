use crate::Os;

// 2.2.4
const MIMALLOC_VERSION: &str = "fbd8b99c2b828428947d70fdc046bb55609be93e";
const FLAGS: &str =
  "-DMI_SECURE=ON -DMI_GUARDED=ON -DMI_BUILD_STATIC=OFF -DMI_BUILD_OBJECT=OFF -DMI_BUILD_TESTS=OFF";

pub fn mimalloc(os: Os) -> String {
  let build_script = |env, flags| {
    format!(
      r#"
#!/bin/sh
set -e

git clone https://github.com/microsoft/mimalloc
cd mimalloc
git checkout {MIMALLOC_VERSION}

# For some reason, `mimalloc` contains binary blobs in the repository, so we remove those now
rm -rf .git ./bin

mkdir -p out/secure
cd out/secure

# `CMakeLists.txt` requires a C++ compiler but `mimalloc` does not use one by default. We claim
# there is a working C++ compiler so CMake doesn't complain, allowing us to not unnecessarily
# install one. If it was ever invoked, our choice of `false` would immediately let us know.
# https://github.com/microsoft/mimalloc/issues/1179
{env} CXX=false cmake -DCMAKE_CXX_COMPILER_WORKS=1 {FLAGS} ../..
make

cd ../..

# Copy the built library to the original directory
cd ..
cp mimalloc/out/secure/libmimalloc-secure.so ./libmimalloc.so
# Clean up the source directory
rm -rf ./mimalloc
  "#
    )
  };

  let build_commands = |env, flags| {
    let mut result = String::new();
    for line in build_script(env, flags)
      .lines()
      .map(|line| {
        assert!(!line.contains('"'));
        format!(r#"RUN echo "{line}" >> ./mimalloc.sh"#)
      })
      .chain(["RUN /bin/sh ./mimalloc.sh", "RUN rm ./mimalloc.sh"].into_iter().map(str::to_string))
    {
      result.push_str(&line);
      result.push('\n');
    }
    result
  };
  let alpine_build = build_commands("CC=$(uname -m)-alpine-linux-musl-gcc", "-DMI_LIBC_MUSL=ON");
  let debian_build = build_commands("", "");

  let alpine_mimalloc = format!(
    r#"
FROM alpine:latest AS mimalloc-alpine

RUN apk update && apk upgrade && apk --no-cache add musl-dev gcc make cmake git

{alpine_build}
"#
  );

  let debian_mimalloc = format!(
    r#"
FROM debian:trixie-slim AS mimalloc-debian

RUN apt update && apt upgrade -y && apt install -y gcc make cmake git

{debian_build}
"#
  );

  match os {
    Os::Alpine => alpine_mimalloc,
    Os::Debian => debian_mimalloc,
  }
}
