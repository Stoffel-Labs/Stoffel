# Stoffel : A framework for building applications using multiparty computation

Stoffel is a comprehensive CLI framework for developing privacy-preserving applications using secure multiparty computation (MPC). It provides tools for project initialization, compilation, development, and deployment of MPC applications using the StoffelLang programming language.

## Features

- **Project Management**: Initialize new MPC projects with language-specific templates
- **StoffelLang Compilation**: Compile `.stfl` source files to executable MPC bytecode
- **Development Tools**: Hot-reloading development server with MPC simulation
- **Multiple Language Support**: Templates for Python, Rust, TypeScript, Solidity, and pure StoffelLang
- **MPC Protocol Integration**: Built-in support for HoneyBadger MPC protocol
- **Comprehensive Help**: Flag-specific help system for all commands and options

## Quick Start

### Installation

Build from source:
```bash
git clone <repository-url>
cd Stoffel
cargo build --release
```

### Create Your First MPC Project

```bash
# Create a new project with Python SDK integration
stoffel init my-mpc-app --template python

# Or create a pure StoffelLang project
stoffel init my-secure-app

# Interactive setup with guided prompts
stoffel init --interactive
```

### Compile Your Project

```bash
# Compile all StoffelLang files in src/
stoffel compile

# Compile a specific file
stoffel compile src/main.stfl

# Generate optimized binary
stoffel compile --binary -O3
```

### Development Server

```bash
# Start development server with MPC simulation
stoffel dev

# Custom configuration
stoffel dev --parties 7 --port 3000 --field bn254
```

## Commands

### `stoffel init`
Initialize new Stoffel projects with proper MPC configuration.

**Templates:**
- `python` - Full Python SDK integration with StoffelProgram and StoffelClient
- `rust` - Rust FFI integration with StoffelVM (development skeleton)
- `typescript` - TypeScript/Node.js client integration (development skeleton)
- `solidity` - Smart contracts with MPC result verification
- `stoffel` - Pure StoffelLang implementation (default)

**Examples:**
```bash
stoffel init my-project                    # Default StoffelLang template
stoffel init --lib my-library              # Create a library project
stoffel init -t python webapp              # Python template
stoffel init -i                           # Interactive setup
```

### `stoffel compile`
Compile StoffelLang source files to executable MPC bytecode.

**Examples:**
```bash
stoffel compile                            # Compile all files in src/
stoffel compile src/main.stfl              # Compile specific file
stoffel compile --binary                   # Generate VM-compatible binaries
stoffel compile -O3                        # Maximum optimization
stoffel compile --disassemble app.bin      # Disassemble compiled binary
```

### `stoffel dev`
Start development server with hot reloading and MPC simulation.

**Examples:**
```bash
stoffel dev                                # Default: 5 parties, port 8080
stoffel dev --parties 7 --port 3000       # Custom configuration
stoffel dev --field bn254                 # Different cryptographic field
```

### `stoffel build`
Build the current project for deployment.

**Examples:**
```bash
stoffel build                              # Debug build
stoffel build --release                    # Production build
stoffel build --target wasm               # WebAssembly target
```

## MPC Configuration

Stoffel uses the HoneyBadger MPC protocol with configurable parameters:

- **Parties**: Minimum 5 parties required for security
- **Threshold**: Maximum corrupted parties = `(parties - 1) / 3`
- **Cryptographic Fields**: BLS12-381 (default), BN254, Secp256k1, Prime61

## Project Structure

```
my-mpc-project/
├── Stoffel.toml              # Project configuration
├── src/                      # StoffelLang source files
│   ├── main.stfl            # Main program entry point
│   └── lib.stfl             # Library functions (for --lib projects)
├── tests/                   # Test files
│   └── integration.stfl     # Integration tests
└── README.md               # Project documentation
```

## Language-Specific Projects

### Python Template
Full SDK integration with Poetry and pytest:
```
my-python-project/
├── pyproject.toml           # Poetry configuration
├── src/
│   ├── main.py             # Python implementation
│   └── secure_computation.stfl  # StoffelLang program
└── tests/
    └── test_main.py        # Python tests
```

### Library Projects
Reusable MPC components:
```bash
stoffel init --lib crypto-utils
```

## Getting Help

Stoffel provides comprehensive help for all commands and flags:

```bash
stoffel --help                    # Main help
stoffel init --help               # Command help
stoffel init -t -h               # Flag-specific help
stoffel compile --binary --help  # Detailed flag documentation
```

## Development

### Building Stoffel

```bash
cargo build                       # Debug build
cargo build --release            # Release build
```

### Running Tests

```bash
cargo test                        # Run Rust tests
```

### Dependencies

Stoffel integrates with:
- **Stoffel-Lang**: StoffelLang compiler for `.stfl` files
- **StoffelVM**: Virtual machine for MPC execution
- **mpc-protocols**: HoneyBadger MPC protocol implementation
- **stoffel-python-sdk**: Python SDK for MPC applications

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Contributing

We welcome meaningful contributions to Stoffel! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.
