# Stoffel browser participant client

This crate is the browser/WASM initialization package for Stoffel participant
clients. It validates browser-addressable coordinator/node endpoints and keeps
participant configuration/state in Rust/WASM.

It does not yet connect, authenticate, secret-share inputs, or submit a
computation. Those operations require a browser transport/identity adapter that
implements `stoffel_client_core::Transport` using the deployed coordinator/node
protocol. In particular, this package does not fall back to loopback, Tauri, or
the native QUIC SDK.

Build gate:

```sh
cargo check -p stoffel-browser-client --target wasm32-unknown-unknown
```

A `wasm-bindgen-test` browser initialization test is included and can be run
with a local browser-capable wasm test runner.
