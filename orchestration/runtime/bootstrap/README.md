# `serai-runtime` Bootstrap

This folder is able to reproducibly build the `serai-runtime`, as part of the
Serai protocol, from a 387-byte binary seed and an extensive amount of source
code\*. It completely\* demonstrates the software supply chain, including the
supply chain to build the supply chain, offering near-complete inspection and
independence.

### Methodology

The current `Containerfile` is premised on
[StageX](https://codeberg.org/stagex/stagex), a Linux distribution which can be
largely bootstrapped from source and the aforementioned 387-byte binary seed.
This is comparable to
[Guix](
  https://guix.gnu.org/en/blog/2023/the-full-source-bootstrap-building-from-source-all-the-way-down
), yet StageX is primarily intended for consumption within an OCI runtime and
its packages are documented to never intentionally outsource to binary blobs
(while some Guix packages are allowed to when bootstrapping isn't possible).

The process is not contained to the `Containerfile` which _MUST NOT_ be used
independently. The process is defined by the `bootstrap.sh` script which builds
the required image from StageX before building the `Containerfile` with the
required context. This build process is expected to take several hours, perhaps
a day even with >16 threads, and require approximately 350 gigabytes of
storage. Please be mindful accordingly.

### Requirements

The host is expected to have a POSIX `sh`, `git`, `cargo`, and `docker` with
`buildx` and the `containerd` backend, along with any dependencies required by
StageX (e.g. `make`, `python >= 3.11`). Bootstrapping will require executing
i386 executables and is only confirmed to work from an x86-64 host.

### Building

```sh
./orchestration/runtime/bootstrap/bootstrap.sh
```

The resulting image will have `busybox` available as a shell and the runtime
located at `/serai.wasm`. Confirming it's a reproduction of the expected
runtime is left to the user. They may export its filesystem to manually inspect
it, derive their own image, or use the included `busybox` (which will also be
built by StageX and reproducible) to output its SHA-256 hash.


#### *

StageX also makes use of multiple binary blobs, albeit not intentionally
according to their own description. These binary blobs are the result of a
near-complete lack of quality assurance applied to the StageX project, causing
binaries to be used in the build process so long as they are not obviously part
of the build process (due to a complete lack of a standard method of filtering
for them and no active investigations/testing occurring to identify any such
instances).

A track record of incidents can be observed with StageX's packaging of
[Ocaml](https://codeberg.org/stagex/stagex/pulls/905) and
[Zig](https://codeberg.org/stagex/stagex/pulls/909), the
[inadvertent usage of a pre-compiled `wasi-sdk`](
  https://codeberg.org/stagex/stagex/pulls/816
) and
[usage of pre-compiled state machines](
  https://codeberg.org/stagex/stagex/pulls/1174
) (an active issue within the latest release, the same used here). As the
project has yet to undergo the work to prove they are in fact bootstrapped,
despite their intent and claims, given the above track record, it likely isn't
reasonable to perpetuate the claim it's bootstrapped. Instead, it should be
acknowledged as _largely bootstrapped_, _reproducible_, and _likely auditable_.
