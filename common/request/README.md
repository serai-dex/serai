# Simple Request

A simple alternative to reqwest, supporting HTTPS, intended to support a
majority of use cases with a fraction of the dependency tree.

This library is built directly around `hyper`, `hyper-rustls`, and does require
`tokio`. Support for `async-std` would be welcome.
