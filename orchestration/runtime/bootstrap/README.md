# `serai-runtime` Bootstrap

This folder is able to reproducibly build the `serai-runtime`, as part of the
Serai protocol, from a 387-byte binary seed and an extensive amount of source
code. It completely demonstrates the software supply chain, including the
supply chain to build the supply chain, offering complete inspection and
independence.

### Methodology

The current `Containerfile` is premised on
[StageX](https://codeberg.org/stagex/stagex), a Linux distribution which can be
bootstrapped entirely from source and the aforementioned 387-byte binary seed.
This is comparable to
[Guix](
  https://guix.gnu.org/en/blog/2023/the-full-source-bootstrap-building-from-source-all-the-way-down
), yet StageX is primarily intended for consumption within an OCI runtime and
its packages never outsource to binary blobs (while some Guix packages are
allowed to when bootstrapping isn't possible).

[kayabaNerve's fork of StageX](https://codeberg.org/kayabaNerve/StageX) is
needed to reproduce the official WASM blob. While StageX offers Rust 1.91.1, it
does so with LLVM 20.1.8 while Rust's official release of 1.91.1 used
LLVM 21.1.2. The cited fork updates StageX to LLVM 21.1.8 and Rust 1.93.0, as
matches the official release of Rust 1.93.0, achieving the expected
reproduction. It also contains miscellaneous bug fixes and tweaks.

The process is not contained to the `Containerfile` which CANNOT be used
independently. The process is defined by the `bootstrap.sh` script which builds
the required container from StageX before building the `Containerfile` with the
required context. This build process is expected to take several hours, perhaps
a day even with >16 threads, and require approximately 350 gigabytes of
storage. Please be mindful accordingly.

### Requirements

The host is expected to have `git`, `make`, `cargo`, and `docker` with
`buildx` and the `containerd` backend, along with any dependencies required by
StageX (e.g. `make`, `python >= 3.11`). Bootstrapping will require executing
x86-64 executables.

### Building

```sh
./orchestration/runtime/bootstrap/bootstrap.sh
```

The resulting image will have `busybox` available as a shell and the runtime
located at `/serai.wasm`. Confirming it's a reproduction of the expected
runtime is left to the user. They may export its filesystem to manually inspect
it, derive their own image, or trust the included `busybox` (which is not
guaranteed to be reproducible) to output its SHA-256 hash.
