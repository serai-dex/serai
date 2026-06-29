# Simple Request

A simple library for making HTTP requests.

This intends to be sufficient as an alternative to
[`reqwest`](https://docs.rs/reqwest) for a large amount of use-cases, but with
a small fraction of the dependencies.

### Implementation

`simple-request` is built directly on top of [`hyper`](https://docs.rs/hyper),
and with the `tls` feature, supports TLS via
[`hyper-rustls`](https://docs.rs/hyper-rustls).

`simple-request` is runtime agnostic but `hyper` does force the inclusion of `tokio`
in the dependency tree. For context, please see
[this issue](https://github.com/serai-dex/serai/issues/682).
