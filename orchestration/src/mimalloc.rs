use crate::Os;

pub fn mimalloc(os: Os) -> &'static str {
  const ALPINE_MIMALLOC: &str = r#"
FROM alpine:latest as mimalloc-alpine

RUN apk update && apk upgrade && apk --no-cache add gcc g++ libc-dev make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  git checkout 43ce4bd7fd34bcc730c1c7471c99995597415488 && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so
"#;

  const DEBIAN_MIMALLOC: &str = r#"
FROM debian:bookworm-slim as mimalloc-debian

RUN apt update && apt upgrade -y && apt install -y gcc g++ make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  git checkout 43ce4bd7fd34bcc730c1c7471c99995597415488 && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so
"#;

  match os {
    Os::Alpine => ALPINE_MIMALLOC,
    Os::Debian => DEBIAN_MIMALLOC,
  }
}
