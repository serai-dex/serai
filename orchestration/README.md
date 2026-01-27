# Orchestration

`serai-orchestrator` generates the `Containerfile`s for a deployment of the
Serai stack and allows starting corresponding containers.

### Portability

This will generate `Containerfile`s valid for the computer the orchestrator is
run on. These `Containerfile`s are not portable, may contain secrets, and MUST
NOT be published.

### Supply Chain Security

The defined `Containerfile`s will build the images for Serai services from
source, only pulling base images such as `rust:slim` to enable building them.
This means building images may take a non-trivial amount of time and a
non-trivial amount of memory. This also means the containers are not at risk of
downloading compromised Serai binaries.

For external networks, the `Containerfile`s will download _and authenticate_
official releases via the stated methods of doing so (generally PGP).

Due to the [complications around using PGP](https://gpg.fail), the
`Containerfile`s make use of both [`gpg`](https://gnupg.org) and
[Sequoia-PGP](https://sequoia-pgp.org) to harden against
implementation-specific issues/misuse. Additionally, Sequoia PGP's chameleon
isn't used but rather its own UI (which attempts to be more modern) to protect
against issues with how Serai invokes these tools (by adding a requirement of
simultaneous misuse of two distinct APIs).

Independent containers are frequently used to build the final image in order to
protect against contamination (an RCE against a verification step which then
contaminates the binary itself).

The base images chosen generally do not pin their version when building/running
services to allow the most up-to-date containers (with the latest set of
patches) to be pulled. This does mean containers may break if unmaintained and
any updates will be automatically accepted however.

### Hardening

Serai attempts to exhaustively apply hardening to its services due to them
being deployed in an incredibly-adversarial environment _and_ accepting
connections over its P2P network(s). The hardening within the services is not
intended to be a replacement for the correct programming of the services
(safety- and correctness-focused development, following of best practices,
external review, auditing of dependencies, using of memory-safe languages,
etc.) nor for the secure deployment of the services (e.g. with proper firewall
configuration on a secure host). It is intended to be a layer against
corruption within code written in a non-memory-safe language (we use RocksDB,
written in C++, and `unsafe` Rust exists) and low-level objects such as the
underlying sockets.

The base images chosen are intended to be minimal, not only for improved
performance but also to reduce any possible attack surface. Separate containers
are used when building services and when running them to downscope to surface
from what's needed to build a service to solely what's needed to run it.

Serai services are built with extensive configuration, notably enabling
overflow checks, stack protection, the
[SafeStack sanitizer](https://clang.llvm.org/docs/SafeStack.html), and pointer
authentication on supported platforms. To ensure `serai-orchestrator` detects
your eligibility properly, please make sure it's built with
`RUSTFLAGS="-C target-cpu=native"` (as it'll defer to the features it itself
has available to determine what the containers will have available). In the
future, we aim to also support
[ControlFlowIntegrity](https://github.com/serai-dex/serai/issues/737) and
[Control-flow Enforcement Technology](
  https://github.com/serai-dex/serai/issues/738
).

When building `debug` builds, such as when testing the Serai stack, Rust's
debug assertions, and undefined behavior checks, are enabled along with
[ASAN](https://clang.llvm.org/docs/AddressSanitizer.html) and randomized
`struct` layouts. While these don't protect the deployed services, they intend
to help catch potential bugs and identify them in test environments.

For running services, [`alpine:latest`](https://hub.docker.com/_/alpine) and
[`debian:stable-slim`](https://hub.docker.com/_/debian) are currently used.
Alpine is _preferred_ yet unfortunately used less often due to how stability
issues may occur when running large services. This is generally considered a
flaw of the services, not of Alpine, as it implies the services require large
amounts of stack or rely on non-standard behavior from their `libc`. As using
Alpine isn't necessary, yet a functional environment is, the solution is
usually the easiest one: base the container on Debian instead. Alternatively,
we have a script, `increase_default_stack_size.sh`, to grant executables a
larger stack when ran by `musl` and potentially resolve any observed
instabilities.

Containers generally make use of
[`mimalloc`](https://github.com/microsoft/mimalloc), compiled with hardening,
for its general performance _and_ improved security (which is accepted as
likely offsetting the performance benefit). This causes programs, regardless of
how they're written or compiled, to benefit from increased scrutiny on their
memory allocations via `malloc`. We have an open issue to also adopt
[`snmalloc`](https://github.com/serai-dex/serai/issues/713) to replace the
allocator monoculture. Additionally, `snmallloc` advertises _distinct_ security
functionality and improved performance, making it independently a valid option.
