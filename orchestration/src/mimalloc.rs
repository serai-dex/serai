use crate::Os;

pub fn mimalloc(os: Os) -> &'static str {
  const ALPINE_MIMALLOC: &str = r#"
FROM alpine:latest AS mimalloc-alpine

RUN apk update && apk upgrade && apk --no-cache add gcc g++ libc-dev make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  git checkout fbd8b99c2b828428947d70fdc046bb55609be93e && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON -DMI_GUARDED=on ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so
"#;

  const DEBIAN_MIMALLOC: &str = r#"
FROM debian:trixie-slim AS mimalloc-debian

RUN apt update && apt upgrade -y && apt install -y gcc g++ make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  git checkout fbd8b99c2b828428947d70fdc046bb55609be93e && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON -DMI_GUARDED=on ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so
"#;

  match os {
    Os::Alpine => ALPINE_MIMALLOC,
    Os::Debian => DEBIAN_MIMALLOC,
  }
}
