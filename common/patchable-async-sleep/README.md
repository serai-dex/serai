# Patchable Async Sleep

An async sleep function, patchable to the preferred runtime.

This crate is `tokio`-backed. Applications which don't want to use `tokio`
should patch this crate to one which works witht heir preferred runtime. The
point of it is to have a minimal API surface to trivially facilitate such work.
