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

- **MPC Protocol Support**: HoneyBadger protocol implementation
- **Cryptographic Fields**: BLS12-381, BN254, Secp256k1, Prime61 support
- **Automatic Parameter Calculation**: Smart defaults for non-cryptographers
- **Parameter Validation**: Ensures protocol security requirements are met
- **StoffelVM Integration**: Multiple optimization levels and party configuration
- ASCII art honeybadger display when run without arguments
- CLI supports verbose output via `-v/--verbose` flag

## MPC Configuration

**Protocol Selection:**
- `--protocol honeybadger` - HoneyBadger protocol (default, minimum 5 parties)

**Security Parameters:**
- `--parties N` - Number of MPC parties (auto-validates based on protocol)
- `--threshold T` - Max corrupted parties (auto-calculated if not provided)
- `--field FIELD` - Cryptographic field (bls12-381, bn254, secp256k1, prime61)

**Examples:**
```bash
# Easy mode - reasonable defaults for non-cryptographers
stoffel dev

# Advanced - specify all parameters
stoffel dev --parties 7 --protocol honeybadger --threshold 2 --field bls12-381

# Testing with different field
stoffel test --field prime61 --parties 5
```

## Related Components

This CLI integrates with:
- **StoffelVM** (`../StoffelVM`) - Register-based MPC virtual machine
- **mpc-protocols** (`../mpc-protocols`) - HoneyBadger MPC protocol implementation

## Dependencies

- `clap` v4.4 with derive features for command-line parsing