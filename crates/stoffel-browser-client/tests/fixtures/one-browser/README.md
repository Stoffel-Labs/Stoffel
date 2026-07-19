# One-browser real-services proof

This fixture proves that a Chromium-hosted `stoffel-browser-client` WASM instance owns four private values, masks them in the browser, and submits them directly to a real off-chain coordinator plus five real MPC party processes over strict-Origin WSS.

Run `./run-one-browser.sh`. Generated keys, capabilities, certificates, logs, WASM glue, bytecode, and browser binaries stay in ignored build/artifact directories. The application HTTP server receives only the browser's public HPKE identity and a value-free receipt; it never receives private prediction values or masked payloads.
