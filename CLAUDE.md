# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Stoffel is a framework for building multiparty computation (MPC) applications. It's implemented as a Rust CLI tool that provides commands for initializing, building, and managing MPC projects.

## Common Development Commands

**Build the project:**
```bash
cargo build
```

**Run the CLI tool:**
```bash
cargo run
cargo run -- <command>
```

**Test the project:**
```bash
cargo test
```

**Check code quality:**
```bash
cargo check
cargo clippy
```

**Format code:**
```bash
cargo fmt
```

## Project Structure

- `src/main.rs` - Main CLI entry point with command definitions
- `Cargo.toml` - Project configuration and dependencies
- The project uses the `clap` crate for CLI argument parsing with the derive feature

## CLI Command Architecture

The main CLI is structured using `clap::Parser` and `clap::Subcommand`:

- **Main Commands** (`Commands` enum): `Init`, `Build`, `Compile`, `Run`, `Test`, `Deploy`, `Version`, `Status`
- **Init Subcommands** (`InitCommands` enum):
  - `Chain` - Initialize projects for specific blockchain chains
  - `Domain` - Initialize projects over computational domains

## Key Features

- CLI supports verbose output via `-v/--verbose` flag
- Optional path parameter via `-p/--path`
- ASCII art honeybadger display when run without arguments
- Framework designed for secure, scalable, and efficient MPC applications

## Dependencies

- `clap` v4.4 with derive features for command-line parsing