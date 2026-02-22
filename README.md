# aspen-plugins

WASM plugins and plugin tooling for the Aspen distributed data platform.

## Overview

This repository contains the official Aspen WASM plugins and the tooling needed to build, sign, and verify them. These plugins extend Aspen's core functionality by implementing various handlers as WebAssembly modules that run in a secure sandbox.

## Plugins

- **aspen-automerge-plugin** - Automerge CRDT document management
- **aspen-coordination-plugin** - Distributed coordination primitives
- **aspen-forge-plugin** - Git forge handler (repos, objects, refs)
- **aspen-hooks-plugin** - Git hooks handler
- **aspen-secrets-plugin** - Secrets engine (KV v2 + Transit)
- **aspen-service-registry-plugin** - Service registry handler
- **aspen-sql-plugin** - SQL query execution

## Tooling

- **aspen-plugin-signing** - Ed25519 signing and verification library
- **cargo-aspen-plugin** - Cargo subcommand for plugin scaffolding, building, signing, and verifying

## Building

All plugins are built as WebAssembly modules using `wasm32-wasip1` target:

```bash
cargo build --release --target wasm32-wasip1
```

## License

AGPL-3.0-or-later
