use clap::{Parser, Subcommand, ValueEnum};

mod init;

/// Stoffel - A framework for building privacy-preserving applications using multiparty computation
#[derive(Parser, Debug)]
#[command(
    name = "stoffel",
    author,
    version,
    about,
    long_about = "Stoffel is a framework for building privacy-preserving applications using multiparty computation"
)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new Stoffel project or library
    #[command(
        long_about = "Initialize a new Stoffel project with proper MPC configuration and project structure.

EXAMPLES:
    stoffel init my-project                    # Create a new project with default StoffelLang template
    stoffel init --lib my-library              # Create a library project
    stoffel init -i                           # Interactive setup with prompts
    stoffel init -t python my-mpc-app         # Create project with Python SDK integration
    stoffel init --path /tmp/test --lib       # Create library at specific path

AVAILABLE TEMPLATES:
    python      - Python SDK integration with StoffelProgram and StoffelClient
    rust        - Rust FFI integration with StoffelVM (skeleton)
    typescript  - TypeScript/Node.js MPC client (skeleton)
    solidity    - Smart contracts with MPC result verification
    stoffel     - Pure StoffelLang implementation (default)

INTERACTIVE MODE:
    Use -i/--interactive to get guided setup with prompts for:
    - Project configuration (name, description, author)
    - MPC parameters (parties, protocol, field type)
    - Template selection with explanations"
    )]
    Init {
        /// Project name (if not provided, uses current directory name)
        #[arg(
            help = "Name of the project to create",
            long_help = "Project name to use for initialization. If not provided, the current directory name will be used. The name should be a valid package identifier (lowercase, hyphens allowed)."
        )]
        name: Option<String>,

        /// Initialize as a library instead of standalone project
        #[arg(
            long,
            help = "Create a library project instead of an application",
            long_help = "Initialize as a library project suitable for publishing and use as a dependency. Libraries include src/lib.stfl and focus on reusable MPC functions rather than executable applications."
        )]
        lib: bool,

        /// Path to initialize in
        #[arg(
            long,
            help = "Directory path where the project should be created",
            long_help = "Path where the new project should be initialized. If not specified, creates the project in the current directory. The path will be created if it doesn't exist."
        )]
        path: Option<String>,

        /// Use interactive mode for setup
        #[arg(
            short,
            long,
            help = "Enable interactive setup with guided prompts",
            long_help = "Interactive mode provides step-by-step setup with prompts for project details, MPC configuration, and template selection. Recommended for first-time users or when you want to customize all settings."
        )]
        interactive: bool,

        /// Template to use for initialization
        #[arg(
            short,
            long,
            help = "Template for project initialization",
            long_help = "Language-specific template to use for project structure:

TEMPLATES:
  python      - Full Python SDK integration with StoffelProgram and StoffelClient
                Creates: src/main.py, pyproject.toml, Poetry configuration

  rust        - Rust FFI integration with StoffelVM (development skeleton)
                Creates: src/main.rs, Cargo.toml with FFI dependencies

  typescript  - TypeScript/Node.js client integration (development skeleton)
                Creates: src/main.ts, package.json, tsconfig.json

  solidity    - Smart contracts with MPC result verification
                Creates: contracts/StoffelMPC.sol, Hardhat configuration

  stoffel     - Pure StoffelLang implementation (default if not specified)
                Creates: src/main.stfl, tests/integration.stfl

The Python template is fully implemented with working SDK integration. Other templates provide development skeletons for their respective ecosystems."
        )]
        template: Option<String>,
    },

    /// Start development server with hot reloading
    #[command(
        long_about = "Start a development server with hot reloading for rapid MPC application development.

EXAMPLES:
    stoffel dev                                # Start dev server with default settings (5 parties, port 8080)
    stoffel dev --parties 7 --port 3000       # Custom party count and port
    stoffel dev --field bn254                 # Use different cryptographic field
    stoffel dev --threshold 2                 # Set custom corruption threshold

DEVELOPMENT FEATURES:
    - Hot reloading: Automatically recompiles and restarts on file changes
    - Local MPC simulation: Simulates distributed computation locally
    - Debug mode: Enhanced logging and debugging information
    - Interactive console: REPL for testing MPC functions

MPC CONFIGURATION:
    The development server simulates a full MPC network locally with the specified
    number of parties. Changes to StoffelLang files trigger automatic recompilation
    and deployment to the simulated network."
    )]
    Dev {
        /// Number of parties for simulation (minimum 5 for HoneyBadger)
        #[arg(
            long,
            default_value = "5",
            help = "Number of MPC parties to simulate",
            long_help = "Number of parties in the simulated MPC network. For HoneyBadger protocol, minimum is 5 parties. More parties increase security but reduce performance. Typical development uses 5-7 parties."
        )]
        parties: u8,

        /// Port to run on
        #[arg(
            short,
            long,
            default_value = "8080",
            help = "Port for the development server",
            long_help = "Port where the development server will listen for connections. The server provides a web interface for monitoring MPC execution and logs."
        )]
        port: u16,

        /// MPC protocol to use
        #[arg(
            long,
            default_value = "honeybadger",
            help = "MPC protocol for simulation",
            long_help = "Multiparty computation protocol to use for development. Currently only HoneyBadger is supported, which provides Byzantine fault tolerance and is production-ready."
        )]
        protocol: MpcProtocol,

        /// Security threshold (max corrupted parties, auto-calculated if not provided)
        #[arg(
            long,
            help = "Maximum number of corrupted parties (auto-calculated if not specified)",
            long_help = "Security threshold: maximum number of parties that can be corrupted while maintaining security. For HoneyBadger, must be < n/3. If not specified, automatically calculated as (parties-1)/3."
        )]
        threshold: Option<u8>,

        /// Field type for computation
        #[arg(
            long,
            default_value = "bls12-381",
            help = "Cryptographic field for MPC operations",
            long_help = "Finite field used for MPC computations:
  bls12-381  - BLS12-381 scalar field (recommended, good performance and security)
  bn254      - BN254 scalar field (alternative pairing-friendly curve)
  secp256k1  - Secp256k1 scalar field (Ethereum/Bitcoin compatibility)
  prime61    - Small prime field for testing (fast but not secure)"
        )]
        field: MpcField,
    },

    /// Compile StoffelLang source files to bytecode
    #[command(
        long_about = "Compile StoffelLang (.stfl) source files into executable MPC bytecode.

DEFAULT BEHAVIOR:
    Without specifying a file, compiles all .stfl files in src/ directory.
    With a file specified, compiles only that specific file.

EXAMPLES:
    stoffel compile                                    # Compile all files in src/
    stoffel compile src/main.stfl                      # Compile specific file
    stoffel compile src/main.stfl -o output.bin        # Specify output file
    stoffel compile --binary                          # Compile all files as binaries
    stoffel compile -O3                               # Compile all with optimization
    stoffel compile --disassemble compiled.bin         # Disassemble compiled binary

BATCH COMPILATION:
    When compiling multiple files from src/:
    - Each file is compiled independently
    - Output files are generated in the same directory structure
    - Compilation continues even if individual files fail
    - Summary report shows success/failure for each file

COMPILATION PROCESS:
    1. Lexical analysis: Tokenizes StoffelLang source
    2. Parsing: Builds Abstract Syntax Tree (AST)
    3. Semantic analysis: Type checking and validation
    4. Code generation: Converts to StoffelVM bytecode
    5. Optimization: Applies requested optimization level
    6. Output: Generates executable bytecode file

OPTIMIZATION LEVELS:
    -O0    No optimization (fastest compilation)
    -O1    Basic optimizations
    -O2    Standard optimizations (good balance)
    -O3    Maximum optimization (slowest compilation)

DEBUGGING:
    Use --print-ir to see intermediate representations during compilation"
    )]
    Compile {
        /// StoffelLang source file to compile (optional - defaults to all files in src/)
        #[arg(
            help = "Path to specific .stfl file to compile (optional)",
            long_help = "Path to the StoffelLang source file (.stfl) to compile. If not specified, compiles all .stfl files in the src/ directory. Can be relative or absolute path. The file must contain valid StoffelLang syntax."
        )]
        file: Option<String>,

        /// Output file path
        #[arg(
            short,
            long,
            help = "Output file path for compiled bytecode",
            long_help = "Specify the output file path for the compiled bytecode. If not provided, uses the input filename with appropriate extension (.bin for binary, .bc for bytecode)."
        )]
        output: Option<String>,

        /// Generate VM-compatible binary
        #[arg(
            short = 'b',
            long,
            help = "Generate VM-compatible binary format",
            long_help = "Generate a VM-compatible binary format suitable for execution on StoffelVM. This is the recommended format for production deployment."
        )]
        binary: bool,

        /// Disassemble compiled binary instead of compiling
        #[arg(
            long,
            help = "Disassemble a compiled binary file",
            long_help = "Disassemble a previously compiled Stoffel binary (.bin) file to show the bytecode instructions. Useful for debugging and understanding compilation output."
        )]
        disassemble: bool,

        /// Print intermediate representations
        #[arg(
            long,
            help = "Print intermediate representations (tokens, AST, etc.)",
            long_help = "Print intermediate representations during compilation including tokens, Abstract Syntax Tree (AST), and other debug information. Useful for compiler development and debugging complex compilation issues."
        )]
        print_ir: bool,

        /// Optimization level (0-3)
        #[arg(
            short = 'O',
            long = "opt-level",
            default_value = "0",
            help = "Set optimization level (0-3)",
            long_help = "Set the optimization level for compilation:
  0  No optimization (fastest compilation, good for development)
  1  Basic optimizations (dead code elimination, constant folding)
  2  Standard optimizations (good balance of speed and size)
  3  Maximum optimization (aggressive optimization, slowest compilation)"
        )]
        opt_level: u8,
    },

    /// Build the current project
    #[command(
        long_about = "Compile the current Stoffel project into executable MPC bytecode.

EXAMPLES:
    stoffel build                              # Debug build with default settings
    stoffel build --release                    # Optimized release build
    stoffel build --target wasm               # Build for WebAssembly target
    stoffel build --optimize --release         # Maximum optimizations for production

BUILD PROCESS:
    1. Compiles StoffelLang (.stfl) files to MPC bytecode
    2. Validates MPC protocol compatibility
    3. Optimizes for the target execution environment
    4. Generates deployment artifacts

OUTPUT:
    - Compiled bytecode in target/ directory
    - Deployment manifests for MPC networks
    - Debug symbols (if debug build)"
    )]
    Build {
        /// Target to build for
        #[arg(
            long,
            help = "Build target platform",
            long_help = "Target platform for compilation:
  native     - Native MPC execution (default)
  wasm       - WebAssembly for browser MPC
  tee        - Trusted Execution Environment
  gpu        - GPU-accelerated computation"
        )]
        target: Option<String>,

        /// Enable optimizations
        #[arg(
            long,
            help = "Enable compiler optimizations",
            long_help = "Enable advanced compiler optimizations for better performance. This includes dead code elimination, constant folding, and MPC-specific optimizations. May increase build time."
        )]
        optimize: bool,

        /// Release build
        #[arg(
            short,
            long,
            help = "Build in release mode with full optimizations",
            long_help = "Release mode enables all optimizations and removes debug information for maximum performance. Use for production deployments. Debug builds are faster to compile and include debugging symbols."
        )]
        release: bool,
    },

    /// Test the current project
    Test {
        /// Run specific test
        #[arg(long)]
        test: Option<String>,

        /// Number of parties for testing (minimum 5 for HoneyBadger)
        #[arg(long, default_value = "5")]
        parties: u8,

        /// MPC protocol to use for testing
        #[arg(long, default_value = "honeybadger")]
        protocol: MpcProtocol,

        /// Security threshold (max corrupted parties, auto-calculated if not provided)
        #[arg(long)]
        threshold: Option<u8>,

        /// Field type for computation
        #[arg(long, default_value = "bls12-381")]
        field: MpcField,

        /// Run integration tests
        #[arg(long)]
        integration: bool,
    },

    /// Run the current project
    Run {
        /// Arguments to pass to the program
        args: Vec<String>,

        /// Number of parties for execution (minimum 5 for HoneyBadger)
        #[arg(long, default_value = "5")]
        parties: u8,

        /// MPC protocol to use for execution
        #[arg(long, default_value = "honeybadger")]
        protocol: MpcProtocol,

        /// Security threshold (max corrupted parties, auto-calculated if not provided)
        #[arg(long)]
        threshold: Option<u8>,

        /// Field type for computation
        #[arg(long, default_value = "bls12-381")]
        field: MpcField,

        /// VM optimization level
        #[arg(long, default_value = "standard")]
        vm_opt: VmOptLevel,
    },

    /// Deploy the current project
    Deploy {
        /// Deployment environment
        #[arg(short, long, default_value = "local")]
        environment: String,

        /// Use TEE deployment
        #[arg(long)]
        tee: bool,

        /// Kubernetes deployment
        #[arg(long)]
        k8s: bool,
    },

    /// Add a dependency to the project
    Add {
        /// Package name
        package: String,

        /// Specific version
        #[arg(long)]
        version: Option<String>,

        /// Add as dev dependency
        #[arg(long)]
        dev: bool,
    },

    /// Publish package to registry
    Publish {
        /// Dry run without actually publishing
        #[arg(long)]
        dry_run: bool,
    },

    /// Install and manage plugins
    Plugin {
        #[command(subcommand)]
        action: PluginCommands,
    },

    /// Check the status of the current project
    Status,

    /// Clean build artifacts
    Clean,

    /// Update dependencies
    Update {
        /// Package to update (all if not specified)
        package: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCommands {
    /// Install a plugin
    Install {
        /// Plugin name
        name: String,
    },

    /// List installed plugins
    List,

    /// Remove a plugin
    Remove {
        /// Plugin name
        name: String,
    },
}

/// Available MPC protocols
#[derive(ValueEnum, Debug, Clone)]
enum MpcProtocol {
    /// HoneyBadger MPC protocol (default, production-ready)
    Honeybadger,
}

/// Available finite fields for MPC computation
#[derive(ValueEnum, Debug, Clone)]
enum MpcField {
    /// BLS12-381 scalar field (default, recommended)
    #[value(name = "bls12-381")]
    Bls12_381,
    /// BN254 scalar field
    #[value(name = "bn254")]
    Bn254,
    /// Secp256k1 scalar field
    #[value(name = "secp256k1")]
    Secp256k1,
    /// Prime field with 61-bit modulus (for testing)
    #[value(name = "prime61")]
    Prime61,
}

/// VM optimization levels
#[derive(ValueEnum, Debug, Clone)]
enum VmOptLevel {
    /// No optimizations (debugging)
    None,
    /// Standard optimizations (default)
    Standard,
    /// Aggressive optimizations (maximum performance)
    Aggressive,
}

fn show_init_template_help() {
    println!(r#"
HELP: stoffel init --template (-t)

DESCRIPTION:
    The --template (-t) flag specifies which programming language ecosystem
    template to use when initializing a new Stoffel project.

USAGE:
    stoffel init --template <TEMPLATE> [PROJECT_NAME]
    stoffel init -t <TEMPLATE> [PROJECT_NAME]

AVAILABLE TEMPLATES:

  python
    ├─ Full Python SDK integration with StoffelProgram and StoffelClient
    ├─ Creates: src/main.py, src/secure_computation.stfl, pyproject.toml
    ├─ Dependencies: Poetry, stoffel-python-sdk
    ├─ Status: ✅ Fully implemented with working MPC examples
    └─ Best for: Python developers, data science, rapid prototyping

  rust
    ├─ Rust FFI integration with StoffelVM (development skeleton)
    ├─ Creates: src/main.rs, Cargo.toml with FFI dependencies
    ├─ Dependencies: libc, tokio (StoffelVM crates when available)
    ├─ Status: 🚧 Development skeleton, FFI integration pending
    └─ Best for: Performance-critical applications, systems programming

  typescript
    ├─ TypeScript/Node.js client integration (development skeleton)
    ├─ Creates: src/main.ts, package.json, tsconfig.json
    ├─ Dependencies: @stoffel/sdk (when available)
    ├─ Status: 🚧 Development skeleton, SDK implementation pending
    └─ Best for: Web applications, JavaScript ecosystem integration

  solidity
    ├─ Smart contracts with MPC result verification
    ├─ Creates: contracts/StoffelMPC.sol, hardhat.config.js, deployment scripts
    ├─ Dependencies: Hardhat, OpenZeppelin contracts
    ├─ Status: 🚧 Development skeleton, on-chain verification concepts
    └─ Best for: Blockchain integration, DeFi applications

  stoffel (default)
    ├─ Pure StoffelLang implementation
    ├─ Creates: src/main.stfl, tests/integration.stfl
    ├─ Dependencies: None (native StoffelLang)
    ├─ Status: ✅ Fully supported with proper syntax
    └─ Best for: Learning StoffelLang, pure MPC applications

EXAMPLES:
    stoffel init -t python my-mpc-app          # Python template
    stoffel init --template rust secure-calc   # Rust template
    stoffel init -t solidity mpc-auction       # Solidity template
    stoffel init my-project                    # Default (stoffel) template

INTERACTIVE MODE:
    Use -i/--interactive to get guided template selection with explanations:

    stoffel init -i                           # Guided setup with template help

For more help: stoffel init --help
"#);
}

fn show_init_interactive_help() {
    println!(r#"
HELP: stoffel init --interactive (-i)

DESCRIPTION:
    The --interactive (-i) flag enables guided setup with step-by-step prompts
    for configuring your new Stoffel project.

USAGE:
    stoffel init --interactive [PROJECT_NAME]
    stoffel init -i [PROJECT_NAME]

INTERACTIVE FEATURES:
    ├─ Project Configuration
    │  ├─ Project name (with validation)
    │  ├─ Description
    │  └─ Author (auto-detected from git config)
    │
    ├─ MPC Configuration
    │  ├─ Number of parties (minimum 5 for HoneyBadger)
    │  ├─ Cryptographic field selection
    │  └─ Security threshold (auto-calculated)
    │
    └─ Template Selection
       ├─ Detailed explanations of each template
       ├─ Recommendations based on use case
       └─ Preview of files that will be created

EXAMPLES:
    stoffel init -i                           # Interactive setup in current directory
    stoffel init -i my-secure-app             # Interactive setup with project name
    stoffel init --interactive --path /tmp    # Interactive setup at specific path

WHEN TO USE:
    ✅ First-time users learning Stoffel
    ✅ When you want to explore all configuration options
    ✅ Setting up complex MPC configurations
    ✅ When unsure which template to choose

For more help: stoffel init --help
"#);
}

fn show_init_lib_help() {
    println!(r#"
HELP: stoffel init --lib

DESCRIPTION:
    The --lib flag creates a library project instead of a standalone application.
    Libraries are designed for reuse and distribution as dependencies.

USAGE:
    stoffel init --lib [PROJECT_NAME]

LIBRARY PROJECT STRUCTURE:
    my-library/
    ├── Stoffel.toml              # Package configuration
    ├── src/
    │   └── lib.stfl              # Library entry point with exported functions
    └── README.md                 # Documentation

LIBRARY FEATURES:
    ├─ Reusable MPC Functions
    │  ├─ Exportable secure computation functions
    │  ├─ Composable privacy-preserving algorithms
    │  └─ Well-defined interfaces for integration
    │
    ├─ Distribution Ready
    │  ├─ Proper package metadata
    │  ├─ Dependency management
    │  └─ Version compatibility
    │
    └─ Testing Infrastructure
       ├─ Unit tests for individual functions
       ├─ Integration tests for MPC workflows
       └─ Benchmarking for performance validation

EXAMPLES:
    stoffel init --lib crypto-utils           # Create cryptographic utilities library
    stoffel init --lib --path ./libs mpc-ml  # Create ML library in specific directory
    stoffel init --lib -i secure-stats       # Interactive library setup

USE CASES:
    ✅ Cryptographic primitives and utilities
    ✅ Domain-specific MPC algorithms (ML, finance, healthcare)
    ✅ Reusable privacy-preserving building blocks
    ✅ Third-party integrations and connectors

For more help: stoffel init --help
"#);
}

fn show_init_path_help() {
    println!(r#"
HELP: stoffel init --path

DESCRIPTION:
    The --path flag specifies where to create the new Stoffel project.
    If the directory doesn't exist, it will be created.

USAGE:
    stoffel init --path <DIRECTORY> [PROJECT_NAME]

PATH BEHAVIOR:
    ├─ Absolute Paths: /home/user/projects/my-app
    ├─ Relative Paths: ./my-project, ../parent-dir/project
    ├─ Auto-creation: Creates directories if they don't exist
    └─ Validation: Ensures write permissions and valid path

EXAMPLES:
    stoffel init --path /tmp/test-project              # Absolute path
    stoffel init --path ./secure-apps my-app           # Relative path
    stoffel init --path ~/Development/MPC secure-calc  # Home directory
    stoffel init --path . existing-dir                 # Current directory

PATH RESOLUTION:
    Without --path:    Uses current directory or creates subdirectory with project name
    With --path:       Creates project at specified location

COMBINED WITH OTHER FLAGS:
    stoffel init --path /tmp --lib my-library          # Library at specific path
    stoffel init --path ./apps -t python webapp        # Python template at path
    stoffel init --path ~/projects -i                  # Interactive at path

VALIDATION:
    ✅ Checks directory write permissions
    ✅ Warns if directory is not empty
    ✅ Creates parent directories as needed
    ⚠️  Fails if path exists and contains Stoffel.toml

For more help: stoffel init --help
"#);
}

// Dev command help functions
fn show_dev_parties_help() {
    println!(r#"
HELP: stoffel dev --parties

DESCRIPTION:
    The --parties flag specifies the number of parties in the simulated MPC network.
    For HoneyBadger protocol, minimum is 5 parties.

USAGE:
    stoffel dev --parties <NUMBER>

PARTY CONFIGURATION:
    Minimum:    5 parties (HoneyBadger protocol requirement)
    Typical:    5-7 parties (good balance of security and performance)
    Maximum:    No hard limit, but performance decreases with more parties

SECURITY IMPLICATIONS:
    ├─ More parties = Higher security against corruption
    ├─ Threshold = (parties - 1) / 3 for HoneyBadger
    ├─ Can tolerate up to threshold corrupted parties
    └─ Example: 7 parties can tolerate 2 corrupted parties

PERFORMANCE CONSIDERATIONS:
    ├─ More parties = More network communication
    ├─ More parties = Slower computation
    ├─ Development typically uses 5-7 parties
    └─ Production may use 10+ parties for higher security

EXAMPLES:
    stoffel dev --parties 5                   # Minimum configuration (fast)
    stoffel dev --parties 7                   # Balanced security/performance
    stoffel dev --parties 10                  # Higher security (slower)

For more help: stoffel dev --help
"#);
}

fn show_dev_port_help() {
    println!(r#"
HELP: stoffel dev --port (-p)

DESCRIPTION:
    The --port (-p) flag specifies which port the development server listens on.
    The server provides a web interface for monitoring MPC execution.

USAGE:
    stoffel dev --port <PORT>
    stoffel dev -p <PORT>

PORT REQUIREMENTS:
    ├─ Range: 1024-65535 (avoid privileged ports < 1024)
    ├─ Available: Port must not be in use by another service
    ├─ Firewall: Ensure port is not blocked by firewall
    └─ Default: 8080 if not specified

DEVELOPMENT SERVER FEATURES:
    ├─ Web Dashboard: Real-time MPC execution monitoring
    ├─ Log Viewer: Detailed logs from all simulated parties
    ├─ Performance Metrics: Computation time, network stats
    ├─ Debug Interface: Inspect MPC state and variables
    └─ Hot Reload Status: File change detection and recompilation

EXAMPLES:
    stoffel dev -p 3000                       # Run on port 3000
    stoffel dev --port 8080                   # Default port (explicit)
    stoffel dev --port 9000 --parties 7       # Custom port with more parties

COMMON PORTS:
    3000    Often used for React/Node.js development
    8080    Default for many development servers
    8000    Alternative development port
    5000    Common for Flask/Python applications

For more help: stoffel dev --help
"#);
}

fn show_dev_protocol_help() {
    println!(r#"
HELP: stoffel dev --protocol

DESCRIPTION:
    The --protocol flag specifies which MPC protocol to use for development.
    Currently only HoneyBadger is supported.

USAGE:
    stoffel dev --protocol <PROTOCOL>

AVAILABLE PROTOCOLS:
    honeybadger (default)
    ├─ Byzantine Fault Tolerant (BFT)
    ├─ Asynchronous network model
    ├─ Threshold: Can tolerate up to (n-1)/3 corrupted parties
    ├─ Minimum parties: 5
    ├─ Security: Production-ready, formally verified
    └─ Performance: Good for most applications

PROTOCOL FEATURES:
    ├─ Robustness
    │  ├─ Works even with network delays and failures
    │  ├─ No synchronization assumptions
    │  └─ Guaranteed termination under honest majority
    │
    ├─ Security
    │  ├─ Information-theoretic security
    │  ├─ Protects against adaptive adversaries
    │  └─ Secure against Byzantine corruption
    │
    └─ Practical
       ├─ Efficient for real-world deployments
       ├─ Scales to reasonable party numbers
       └─ Well-tested implementation

EXAMPLES:
    stoffel dev --protocol honeybadger        # Explicit protocol selection
    stoffel dev                               # Uses honeybadger by default

FUTURE PROTOCOLS:
    Additional protocols may be added in future versions based on:
    ├─ Research advances in MPC protocols
    ├─ Specific use case requirements (speed vs security)
    └─ Community feedback and requests

For more help: stoffel dev --help
"#);
}

fn show_dev_threshold_help() {
    println!(r#"
HELP: stoffel dev --threshold

DESCRIPTION:
    The --threshold flag sets the maximum number of parties that can be corrupted
    while maintaining security. Auto-calculated if not specified.

USAGE:
    stoffel dev --threshold <NUMBER>

THRESHOLD CALCULATION:
    For HoneyBadger protocol: threshold = (parties - 1) / 3

    Examples:
    ├─ 5 parties → threshold 1 (can tolerate 1 corrupted party)
    ├─ 7 parties → threshold 2 (can tolerate 2 corrupted parties)
    ├─ 10 parties → threshold 3 (can tolerate 3 corrupted parties)
    └─ 16 parties → threshold 5 (can tolerate 5 corrupted parties)

SECURITY IMPLICATIONS:
    ├─ Higher threshold = More fault tolerance
    ├─ Lower threshold = Less fault tolerance but faster
    ├─ Threshold must be < parties/3 for HoneyBadger
    └─ Invalid thresholds will cause initialization to fail

WHEN TO CUSTOMIZE:
    ├─ Testing specific threat models
    ├─ Simulating network with known number of adversaries
    ├─ Performance testing with different security levels
    └─ Research and experimentation

EXAMPLES:
    stoffel dev --parties 7 --threshold 1     # Lower security, faster
    stoffel dev --parties 7                   # Auto: threshold = 2
    stoffel dev --parties 10 --threshold 3    # Explicit threshold

VALIDATION:
    ✅ threshold < (parties + 2) / 3
    ⚠️  Too high threshold will fail with security error
    ⚠️  Too low threshold reduces security unnecessarily

For more help: stoffel dev --help
"#);
}

fn show_dev_field_help() {
    println!(r#"
HELP: stoffel dev --field

DESCRIPTION:
    The --field flag specifies the finite field used for MPC computations.
    Different fields offer different performance and compatibility characteristics.

USAGE:
    stoffel dev --field <FIELD>

AVAILABLE FIELDS:

  bls12-381 (default)
    ├─ Security: ~128-bit security level
    ├─ Performance: Good balance of speed and security
    ├─ Compatibility: Works with BLS signatures and pairings
    ├─ Size: ~381-bit prime field
    └─ Best for: General-purpose MPC applications

  bn254
    ├─ Security: ~100-bit security level
    ├─ Performance: Faster than BLS12-381
    ├─ Compatibility: Ethereum's alt_bn128 precompiles
    ├─ Size: ~254-bit prime field
    └─ Best for: Ethereum integration, when speed matters

  secp256k1
    ├─ Security: ~128-bit security level
    ├─ Performance: Good, widely optimized
    ├─ Compatibility: Bitcoin/Ethereum ECDSA curve
    ├─ Size: ~256-bit prime field
    └─ Best for: Cryptocurrency applications

  prime61
    ├─ Security: ⚠️ Testing only (not secure)
    ├─ Performance: Very fast
    ├─ Compatibility: Simple operations
    ├─ Size: 61-bit prime field
    └─ Best for: Development, testing, benchmarking

SELECTION CRITERIA:
    ├─ Security Requirements: Choose field with adequate security level
    ├─ Performance Needs: Smaller fields are faster but less secure
    ├─ Integration: Match field to existing cryptographic infrastructure
    └─ Development Phase: Use prime61 for fast iteration, production fields for release

EXAMPLES:
    stoffel dev --field bls12-381             # Default, good for most use cases
    stoffel dev --field bn254                 # Ethereum-compatible
    stoffel dev --field prime61               # Fast development/testing
    stoffel dev --field secp256k1             # Bitcoin/crypto compatibility

For more help: stoffel dev --help
"#);
}

// Build command help functions
fn show_build_target_help() {
    println!(r#"
HELP: stoffel build --target

DESCRIPTION:
    The --target flag specifies the platform to build for.
    Different targets enable deployment to different environments.

USAGE:
    stoffel build --target <TARGET>

AVAILABLE TARGETS:

  native (default)
    ├─ Native MPC execution on the current platform
    ├─ Best performance for local and server deployment
    ├─ Full feature support
    └─ Direct integration with system resources

  wasm
    ├─ WebAssembly for browser-based MPC
    ├─ Cross-platform compatibility
    ├─ Sandboxed execution environment
    └─ Web application integration

  tee
    ├─ Trusted Execution Environment (Intel SGX, ARM TrustZone)
    ├─ Hardware-based security guarantees
    ├─ Additional protection against side-channel attacks
    └─ Cloud deployment with confidential computing

  gpu
    ├─ GPU-accelerated computation
    ├─ Parallel processing for large-scale MPC
    ├─ Optimized for computationally intensive operations
    └─ Requires CUDA or OpenCL support

EXAMPLES:
    stoffel build --target native             # Default native build
    stoffel build --target wasm               # Browser deployment
    stoffel build --target tee                # Confidential computing
    stoffel build --target gpu                # High-performance computing

For more help: stoffel build --help
"#);
}

fn show_build_optimize_help() {
    println!(r#"
HELP: stoffel build --optimize

DESCRIPTION:
    The --optimize flag enables advanced compiler optimizations for better performance.
    This may increase build time but improves runtime performance.

USAGE:
    stoffel build --optimize

OPTIMIZATION FEATURES:
    ├─ Dead Code Elimination: Removes unused functions and variables
    ├─ Constant Folding: Pre-computes constant expressions
    ├─ Loop Optimization: Improves loop performance and memory usage
    ├─ MPC-Specific: Optimizations for secure computation patterns
    └─ Bytecode Optimization: Generates more efficient VM instructions

PERFORMANCE IMPACT:
    ├─ Runtime Speed: 20-50% faster execution typical
    ├─ Memory Usage: Reduced memory footprint
    ├─ Network Traffic: Optimized communication patterns
    └─ Build Time: Increased compilation time

WHEN TO USE:
    ✅ Production builds
    ✅ Performance testing
    ✅ Final deployment artifacts
    ⚠️  Not recommended for debug builds (harder to debug)

EXAMPLES:
    stoffel build --optimize                  # Optimized debug build
    stoffel build --optimize --release        # Full optimization
    stoffel build --optimize --target wasm    # Optimized WebAssembly

OPTIMIZATION LEVELS:
    Without --optimize:    Fast compilation, basic optimizations
    With --optimize:       Advanced optimizations, slower compilation
    With --release:        Maximum optimizations (implies --optimize)

For more help: stoffel build --help
"#);
}

fn show_build_release_help() {
    println!(r#"
HELP: stoffel build --release (-r)

DESCRIPTION:
    The --release (-r) flag builds in release mode with maximum optimizations
    and no debug information. This is the recommended mode for production.

USAGE:
    stoffel build --release
    stoffel build -r

RELEASE BUILD FEATURES:
    ├─ Maximum Optimizations: All optimization passes enabled
    ├─ No Debug Info: Smaller binary size, faster loading
    ├─ Production Ready: Suitable for deployment
    ├─ Security Hardening: Additional security measures
    └─ Performance Tuned: Optimized for runtime performance

DIFFERENCES FROM DEBUG:
    Debug Build:
    ├─ Fast compilation
    ├─ Debug symbols included
    ├─ Assertions enabled
    ├─ Larger binary size
    └─ Easier debugging

    Release Build:
    ├─ Slower compilation
    ├─ No debug symbols
    ├─ Assertions disabled
    ├─ Smaller binary size
    └─ Maximum performance

BUILD ARTIFACTS:
    ├─ Optimized bytecode in target/release/
    ├─ Deployment manifests
    ├─ Production configuration templates
    └─ Performance reports

EXAMPLES:
    stoffel build -r                          # Standard release build
    stoffel build --release --target wasm     # Release WebAssembly build
    stoffel build --release --target tee      # Release TEE build

DEPLOYMENT CHECKLIST:
    ✅ Build with --release flag
    ✅ Test on target environment
    ✅ Verify performance requirements
    ✅ Security audit if required

For more help: stoffel build --help
"#);
}

// Compile command help functions
fn show_compile_output_help() {
    println!(r#"
HELP: stoffel compile --output (-o)

DESCRIPTION:
    The --output (-o) flag specifies the output file path for compiled bytecode.
    If not provided, uses the input filename with appropriate extension.

USAGE:
    stoffel compile src/main.stfl --output compiled.bin
    stoffel compile src/main.stfl -o output.bc

OUTPUT FILE EXTENSIONS:
    .bin    VM-compatible binary (use with --binary flag)
    .bc     Bytecode format (default)
    .stfl   Source file extension (input files)

FILE PATH RESOLUTION:
    ├─ Absolute paths: /path/to/output.bin
    ├─ Relative paths: ./output.bin, ../compiled/main.bc
    ├─ Automatic extension: Adds .bc if no extension provided
    └─ Directory creation: Creates parent directories if needed

EXAMPLES:
    stoffel compile main.stfl -o compiled.bin          # Specific output file
    stoffel compile main.stfl --output release.bc     # Bytecode output
    stoffel compile main.stfl -o /tmp/test.bin         # Absolute path
    stoffel compile main.stfl                          # Auto: main.bc

INTEGRATION WITH OTHER FLAGS:
    stoffel compile main.stfl -o app.bin --binary     # Binary format output
    stoffel compile main.stfl -o debug.bc --print-ir  # Debug output with IR
    stoffel compile main.stfl -o opt.bin -O3 --binary # Optimized binary

For more help: stoffel compile --help
"#);
}

fn show_compile_binary_help() {
    println!(r#"
HELP: stoffel compile --binary (-b)

DESCRIPTION:
    The --binary (-b) flag generates VM-compatible binary format suitable
    for execution on StoffelVM. This is the recommended format for production.

USAGE:
    stoffel compile src/main.stfl --binary
    stoffel compile src/main.stfl -b

BINARY FORMAT FEATURES:
    ├─ VM Compatibility: Direct execution on StoffelVM
    ├─ Optimized Loading: Faster startup times
    ├─ Compact Size: Efficient binary representation
    ├─ Production Ready: Suitable for deployment
    └─ Platform Independent: Runs on any StoffelVM instance

BINARY VS BYTECODE:
    Bytecode (.bc):
    ├─ Human-readable representation
    ├─ Debugging friendly
    ├─ Larger file size
    └─ Requires additional processing

    Binary (.bin):
    ├─ VM-optimized format
    ├─ Faster execution
    ├─ Smaller file size
    └─ Production deployment

EXAMPLES:
    stoffel compile main.stfl --binary                 # Generate binary
    stoffel compile main.stfl -b -o release.bin        # Binary with custom name
    stoffel compile main.stfl --binary -O3             # Optimized binary

DEPLOYMENT WORKFLOW:
    1. Development: Compile without --binary for debugging
    2. Testing: Use --binary for performance testing
    3. Production: Always use --binary for deployment

For more help: stoffel compile --help
"#);
}

fn show_compile_disassemble_help() {
    println!(r#"
HELP: stoffel compile --disassemble

DESCRIPTION:
    The --disassemble flag disassembles a compiled binary file to show
    bytecode instructions. Useful for debugging and understanding compilation.

USAGE:
    stoffel compile compiled.bin --disassemble

DISASSEMBLY FEATURES:
    ├─ Bytecode Instructions: Shows VM opcodes and operands
    ├─ Memory Layout: Displays data section and constants
    ├─ Jump Targets: Shows labels and branch destinations
    ├─ Debug Information: Includes source line mappings (if available)
    └─ Human Readable: Formatted output for analysis

INPUT FILE TYPES:
    .bin    VM-compatible binary files
    .bc     Bytecode files (also supported)

DISASSEMBLY OUTPUT:
    ├─ Instruction listing with addresses
    ├─ Register usage and data flow
    ├─ Function boundaries and call sites
    └─ Constant pool and literal values

EXAMPLES:
    stoffel compile app.bin --disassemble              # Disassemble binary
    stoffel compile debug.bc --disassemble             # Disassemble bytecode
    stoffel compile app.bin --disassemble > dump.txt   # Save to file

DEBUGGING WORKFLOW:
    1. Compile with debug info: stoffel compile main.stfl --print-ir
    2. Generate binary: stoffel compile main.stfl --binary -o app.bin
    3. Disassemble: stoffel compile app.bin --disassemble
    4. Analyze output for optimization opportunities

COMMON USE CASES:
    ✅ Debugging compilation issues
    ✅ Understanding compiler optimizations
    ✅ Reverse engineering binary files
    ✅ Performance analysis and profiling

For more help: stoffel compile --help
"#);
}

fn show_compile_print_ir_help() {
    println!(r#"
HELP: stoffel compile --print-ir

DESCRIPTION:
    The --print-ir flag prints intermediate representations during compilation,
    including tokens, AST, and other debug information.

USAGE:
    stoffel compile src/main.stfl --print-ir

INTERMEDIATE REPRESENTATIONS:
    ├─ Tokens: Lexical analysis output (keywords, identifiers, literals)
    ├─ Abstract Syntax Tree (AST): Parsed program structure
    ├─ Symbol Table: Variable and function declarations
    ├─ Type Information: Inferred and declared types
    ├─ Semantic Analysis: Type checking and validation results
    └─ Code Generation: Bytecode generation steps

DEBUG OUTPUT SECTIONS:
    1. LEXICAL ANALYSIS
       ├─ Token stream with positions
       ├─ Keyword recognition
       └─ Literal parsing

    2. SYNTAX ANALYSIS
       ├─ Parse tree structure
       ├─ Grammar rule applications
       └─ Error recovery attempts

    3. SEMANTIC ANALYSIS
       ├─ Type checking results
       ├─ Symbol resolution
       └─ Scope analysis

    4. CODE GENERATION
       ├─ Bytecode instruction selection
       ├─ Register allocation
       └─ Optimization passes

EXAMPLES:
    stoffel compile main.stfl --print-ir               # Full IR output
    stoffel compile main.stfl --print-ir > debug.log   # Save to file
    stoffel compile main.stfl --print-ir -O2           # IR with optimizations

DEBUGGING WORKFLOW:
    1. Basic compilation: Check for syntax errors
    2. Add --print-ir: Examine parse tree and types
    3. Fix issues: Use IR to identify problems
    4. Optimize: Compare IR before/after optimization

WHEN TO USE:
    ✅ Debugging compilation errors
    ✅ Understanding compiler behavior
    ✅ Learning StoffelLang internals
    ✅ Contributing to compiler development
    ⚠️  Produces verbose output (use redirection)

For more help: stoffel compile --help
"#);
}

fn show_compile_opt_level_help() {
    println!(r#"
HELP: stoffel compile --opt-level (-O)

DESCRIPTION:
    The --opt-level (-O) flag sets the optimization level for compilation.
    Higher levels improve performance but increase compilation time.

USAGE:
    stoffel compile src/main.stfl --opt-level 2
    stoffel compile src/main.stfl -O3

OPTIMIZATION LEVELS:

  -O0 (default)
    ├─ No optimization
    ├─ Fastest compilation
    ├─ Best for development and debugging
    ├─ Preserves all debug information
    └─ Larger bytecode size

  -O1
    ├─ Basic optimizations
    ├─ Dead code elimination
    ├─ Constant folding
    ├─ Fast compilation
    └─ Good balance for development

  -O2
    ├─ Standard optimizations
    ├─ Loop optimizations
    ├─ Function inlining (small functions)
    ├─ Register optimization
    └─ Recommended for production

  -O3
    ├─ Aggressive optimizations
    ├─ Advanced loop transformations
    ├─ Extensive function inlining
    ├─ Cross-function optimizations
    └─ Maximum performance (slowest compilation)

OPTIMIZATION TECHNIQUES:
    ├─ Dead Code Elimination: Removes unused code
    ├─ Constant Folding: Pre-computes constant expressions
    ├─ Loop Optimization: Reduces loop overhead
    ├─ Function Inlining: Eliminates function call overhead
    ├─ Register Allocation: Optimizes register usage
    └─ MPC-Specific: Optimizes secure computation patterns

PERFORMANCE IMPACT:
    Level    Compile Time    Runtime Speed    Binary Size
    -O0      Fastest        Slowest          Largest
    -O1      Fast           Good             Medium
    -O2      Medium         Better           Smaller
    -O3      Slowest        Fastest          Smallest

EXAMPLES:
    stoffel compile main.stfl -O0                      # Debug build
    stoffel compile main.stfl -O2                      # Production build
    stoffel compile main.stfl -O3 --binary             # Maximum optimization
    stoffel compile main.stfl --opt-level 1            # Explicit level 1

WHEN TO USE EACH LEVEL:
    -O0: Development, debugging, rapid iteration
    -O1: Testing builds, continuous integration
    -O2: Production releases, performance testing
    -O3: Performance-critical applications, benchmarking

For more help: stoffel compile --help
"#);
}

// Placeholder functions for other commands to avoid compile errors
fn show_test_test_help() { println!("Help for --test flag coming soon"); }
fn show_test_parties_help() { println!("Help for --parties flag coming soon"); }
fn show_test_protocol_help() { println!("Help for --protocol flag coming soon"); }
fn show_test_threshold_help() { println!("Help for --threshold flag coming soon"); }
fn show_test_field_help() { println!("Help for --field flag coming soon"); }
fn show_test_integration_help() { println!("Help for --integration flag coming soon"); }
fn show_run_parties_help() { println!("Help for --parties flag coming soon"); }
fn show_run_protocol_help() { println!("Help for --protocol flag coming soon"); }
fn show_run_threshold_help() { println!("Help for --threshold flag coming soon"); }
fn show_run_field_help() { println!("Help for --field flag coming soon"); }
fn show_run_vm_opt_help() { println!("Help for --vm-opt flag coming soon"); }

fn display_honeybadger() {
    println!(r#"
    Stoffel is a honeybadger that helps you build MPC applications.
    Honeybadgers are a fearless breed of animals that are known for their tenacity and resilience.
    MPC is a powerful tool that allows you to build applications that are secure, scalable, and efficient. Just like Stoffel.

                                                                                                                                                  
                                                   @    .                                           
                                                @@@@@@@@@*@@                                        
                                              @@+-@   --@@@@                                        
                                          @@@@ --------------@@@                                    
                                     @@@@   -----------------@@@@@                                  
                                 @@@@  ---------------------------@@@@                              
                              *@@@  :::::::::::::::::::-------------- @@@                           
                            @@@  :::::::::::::::::::::::::::------------ @@                         
                          @@@  :::::::::::::::::::::::::::::::::-*----%--- @@                       
                         @@  :+=%%%%%%%%@%@@@:::::::::::::@::::=%%@%@-@%%%@- @@                     
                       @@:%%%%%%%%%%%%#########%::::::::##%%%%%%%%%%%%%%%%%%%@ @@.                  
                      @@-%%%%%%%%%################@:@#########################%@@@                  
                     @:#%%#######################################################@@                 
                   @@:#############@@#############################%@##############:@                
                  @@:##################@#######################@###################@@@@##@@         
           @@##@@@@:######################@#################@*######################@###@#@         
          @@#@####:########################*@#############@++##########################%%@@@.       
          @#%%%#############################+@###########@++##########################@%%%@@        
          @#%%%%##########@@=====@@@@@######++%#####****%@+*#####@@@@@@====@@#########%%%%%@        
         #@#%%%%@##########@=====@  @@@@@@###+%*********%@***#@% @@@@@=====@#########@#@%%%@        
          @#%%@#############@....@%%%%%%@@#**@***********#***@@  %%%%@....@############@%%@@        
          @:%%%@###########*#@....@%####.-*******##@@@##*****@.%%%@@@....@@*############%#@@        
          @##%@##############*++@@..@@@...*****++++++++++****+  @@@..@@++*############%%%:@         
           @#%%%#################++#####@.*********@@@******* @*****#+++##############%%:@%         
           @@#%%########################****@%%%%%%%%%%%%%%@********###################:@@          
            @@%:#########%%@@@%%%#######***@@@@   .        @@*******####%%@@%%########:@@           
             @@:##############@##########***%%%@%%%%%%%%%%%%********##%#@@############@:@           
             @@##%#############@##########***%%%#%%%%%%@%%%********####@=#############:@@@          
             @:%%##############@=#############**@#%%%%#@*********#####@=##############:@            
            .@%%@#%%############@=#######@#########@%################@=#############%##@+           
            @@#@:#%%#############==@###############################%=@@#############%#:@            
               @:%%%%#############@=.@%#######%%%%%%%%%%%#######%%@.=@#############%%%:@            
               @@%%%%%%%###########=..@=.@@@@@@@@-....@@@@@@@@@==@..@##############:%:@@            
               @@%@:%%%%%###########=..==......................=@.==###########%:#:@@:@             
                @%@@:%%%%%%#########@..@=...@...=@....@=..@...==...###########%:%:@@@@              
                @@  @:%%%%%%%%########..=..@..................=@.@#######%%#%:@@:@@                 
                     @@:%@::%%%%#######@-=@.................=.=@#######%%%%%:@@@@                   
                       @@:@@@::%%%%##########@@@@@@@@@@@@@%##@#######%%:%%:@@                       
                          @@@@@@::%@:%#############################%::@@%@@                         
                                 @@:@@@::######################%:%:@@ @:@                           
                                    @@ @@@:%%%%############%%%:*@@                                  
                                           @@::@:%%%%%%:%%:@%:@                                     
                                             @@@@@:::@@+@@@@@                                       
                                                    @ +                                             
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    


"#);
}

fn main() -> Result<(), String> {
    // Handle special flag-specific help cases before clap parsing
    let args: Vec<String> = std::env::args().collect();

    // Check for flag-specific help patterns like "stoffel init -t -h" or "stoffel dev --parties --help"
    if args.len() >= 4 {
        let command = args.get(1).map(|s| s.as_str());
        let flag = args.get(2).map(|s| s.as_str());
        let help_flag = args.get(3).map(|s| s.as_str());

        if help_flag == Some("-h") || help_flag == Some("--help") {
            match (command, flag) {
                // Init command flags
                (Some("init"), Some("-t" | "--template")) => {
                    show_init_template_help();
                    return Ok(());
                }
                (Some("init"), Some("-i" | "--interactive")) => {
                    show_init_interactive_help();
                    return Ok(());
                }
                (Some("init"), Some("--lib")) => {
                    show_init_lib_help();
                    return Ok(());
                }
                (Some("init"), Some("--path")) => {
                    show_init_path_help();
                    return Ok(());
                }

                // Dev command flags
                (Some("dev"), Some("--parties")) => {
                    show_dev_parties_help();
                    return Ok(());
                }
                (Some("dev"), Some("-p" | "--port")) => {
                    show_dev_port_help();
                    return Ok(());
                }
                (Some("dev"), Some("--protocol")) => {
                    show_dev_protocol_help();
                    return Ok(());
                }
                (Some("dev"), Some("--threshold")) => {
                    show_dev_threshold_help();
                    return Ok(());
                }
                (Some("dev"), Some("--field")) => {
                    show_dev_field_help();
                    return Ok(());
                }

                // Build command flags
                (Some("build"), Some("--target")) => {
                    show_build_target_help();
                    return Ok(());
                }
                (Some("build"), Some("--optimize")) => {
                    show_build_optimize_help();
                    return Ok(());
                }
                (Some("build"), Some("-r" | "--release")) => {
                    show_build_release_help();
                    return Ok(());
                }

                // Test command flags
                (Some("test"), Some("--test")) => {
                    show_test_test_help();
                    return Ok(());
                }
                (Some("test"), Some("--parties")) => {
                    show_test_parties_help();
                    return Ok(());
                }
                (Some("test"), Some("--protocol")) => {
                    show_test_protocol_help();
                    return Ok(());
                }
                (Some("test"), Some("--threshold")) => {
                    show_test_threshold_help();
                    return Ok(());
                }
                (Some("test"), Some("--field")) => {
                    show_test_field_help();
                    return Ok(());
                }
                (Some("test"), Some("--integration")) => {
                    show_test_integration_help();
                    return Ok(());
                }

                // Compile command flags
                (Some("compile"), Some("-o" | "--output")) => {
                    show_compile_output_help();
                    return Ok(());
                }
                (Some("compile"), Some("-b" | "--binary")) => {
                    show_compile_binary_help();
                    return Ok(());
                }
                (Some("compile"), Some("--disassemble")) => {
                    show_compile_disassemble_help();
                    return Ok(());
                }
                (Some("compile"), Some("--print-ir")) => {
                    show_compile_print_ir_help();
                    return Ok(());
                }
                (Some("compile"), Some("-O" | "--opt-level")) => {
                    show_compile_opt_level_help();
                    return Ok(());
                }

                // Run command flags
                (Some("run"), Some("--parties")) => {
                    show_run_parties_help();
                    return Ok(());
                }
                (Some("run"), Some("--protocol")) => {
                    show_run_protocol_help();
                    return Ok(());
                }
                (Some("run"), Some("--threshold")) => {
                    show_run_threshold_help();
                    return Ok(());
                }
                (Some("run"), Some("--field")) => {
                    show_run_field_help();
                    return Ok(());
                }
                (Some("run"), Some("--vm-opt")) => {
                    show_run_vm_opt_help();
                    return Ok(());
                }

                _ => {}
            }
        }
    }

    let cli = Cli::parse();

    // If no subcommand is provided, show the honeybadger
    if std::env::args().len() == 1 {
        display_honeybadger();
        return Ok(());
    }

    if cli.verbose {
        println!("Running command: {:?}", cli.command);
    }

    match cli.command {
        Commands::Init { name, lib, path, interactive, template } => {
            let init_options = init::InitOptions {
                name,
                lib,
                path,
                interactive,
                template,
            };

            if let Err(e) = init::initialize_project(init_options) {
                eprintln!("❌ Initialization failed: {}", e);
                std::process::exit(1);
            }
        }

        Commands::Compile { file, output, binary, disassemble, print_ir, opt_level } => {
            // Validate optimization level
            if opt_level > 3 {
                eprintln!("❌ Invalid optimization level: {}. Must be 0-3.", opt_level);
                std::process::exit(1);
            }

            // Build the path to the Stoffel-Lang compiler
            let exe_path = std::env::current_exe()
                .map_err(|e| format!("Failed to get executable path: {}", e))?;
            let exe_dir = exe_path.parent()
                .ok_or("Failed to get executable directory")?;

            // Navigate to parent directory to find Stoffel-Lang
            let stoffel_lang_path = exe_dir.parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .map(|p| p.join("Stoffel-Lang"))
                .ok_or("Could not locate Stoffel-Lang directory")?;

            let compiler_path = stoffel_lang_path.join("target").join("debug").join("stoffellang");

            // Check if Stoffel-Lang compiler exists
            if !compiler_path.exists() {
                eprintln!("❌ Stoffel-Lang compiler not found at: {}", compiler_path.display());
                eprintln!("   Please build Stoffel-Lang first:");
                eprintln!("   cd {} && cargo build", stoffel_lang_path.display());
                std::process::exit(1);
            }

            match file {
                Some(specific_file) => {
                    // Compile specific file
                    if disassemble {
                        println!("🔧 Disassembling file: {}", specific_file);
                    } else {
                        println!("🔧 Compiling StoffelLang file: {}", specific_file);
                    }

                    let success = compile_single_file(&compiler_path, &specific_file, &output, binary, disassemble, print_ir, opt_level)?;
                    if !success {
                        std::process::exit(1);
                    }
                }
                None => {
                    // Compile all files in src/ directory
                    println!("🔧 Compiling all StoffelLang files in src/ directory...");

                    // Check if src/ directory exists
                    if !std::path::Path::new("src").exists() {
                        eprintln!("❌ No src/ directory found. Please run this command from a Stoffel project root,");
                        eprintln!("   or specify a specific file to compile.");
                        std::process::exit(1);
                    }

                    // Find all .stfl files in src/
                    let stfl_files = find_stfl_files("src")?;

                    if stfl_files.is_empty() {
                        println!("ℹ️  No .stfl files found in src/ directory.");
                        return Ok(());
                    }

                    println!("   Found {} StoffelLang file(s) to compile:", stfl_files.len());
                    for file in &stfl_files {
                        println!("     - {}", file);
                    }
                    println!();

                    // Compile each file
                    let mut successful = 0;
                    let mut failed = 0;

                    for stfl_file in &stfl_files {
                        println!("🔧 Compiling: {}", stfl_file);

                        // For batch compilation, don't use custom output names (they would conflict)
                        let file_output = if output.is_some() && stfl_files.len() > 1 {
                            eprintln!("⚠️  Custom output path ignored for batch compilation");
                            None
                        } else {
                            output.clone()
                        };

                        let success = compile_single_file(&compiler_path, stfl_file, &file_output, binary, disassemble, print_ir, opt_level)?;

                        if success {
                            successful += 1;
                            println!("✅ {}", stfl_file);
                        } else {
                            failed += 1;
                            println!("❌ {}", stfl_file);
                        }
                        println!();
                    }

                    // Summary
                    println!("📊 Compilation Summary:");
                    println!("   ✅ Successful: {}", successful);
                    println!("   ❌ Failed: {}", failed);
                    println!("   📁 Total: {}", stfl_files.len());

                    if failed > 0 {
                        std::process::exit(1);
                    } else {
                        println!("🎉 All files compiled successfully!");
                    }
                }
            }
        }

        Commands::Dev { parties, port, protocol, threshold, field } => {
            println!("🔧 Starting development server...");
            println!("   Parties: {}", parties);
            println!("   Port: {}", port);
            println!("   Protocol: {:?}", protocol);
            println!("   Field: {:?}", field);

            let threshold = threshold.unwrap_or_else(|| calculate_threshold(parties, &protocol));
            println!("   Threshold: {}", threshold);

            validate_mpc_params(parties, threshold, &protocol)?;

            println!("   [TODO: Initialize StoffelVM with {} parties]", parties);
            println!("   [TODO: Setup {} protocol with threshold {}]", format!("{:?}", protocol).to_lowercase(), threshold);
            println!("   [TODO: Start hot reloading server on port {}]", port);
        }

        Commands::Build { target, optimize, release } => {
            println!("🔨 Building project...");
            if release {
                println!("   Mode: Release");
            } else {
                println!("   Mode: Debug");
            }
            if let Some(target) = target {
                println!("   Target: {}", target);
            }
            if optimize {
                println!("   Optimizations: Enabled");
            }
            println!("   [TODO: Implement build logic]");
        }

        Commands::Test { test, parties, protocol, threshold, field, integration } => {
            println!("🧪 Running tests...");
            println!("   Parties: {}", parties);
            println!("   Protocol: {:?}", protocol);
            println!("   Field: {:?}", field);

            let threshold = threshold.unwrap_or_else(|| calculate_threshold(parties, &protocol));
            println!("   Threshold: {}", threshold);

            validate_mpc_params(parties, threshold, &protocol)?;

            if let Some(test) = test {
                println!("   Specific test: {}", test);
            }
            if integration {
                println!("   Type: Integration tests");
            }
            println!("   [TODO: Initialize test environment with {} parties]", parties);
            println!("   [TODO: Setup {} protocol for testing]", format!("{:?}", protocol).to_lowercase());
        }

        Commands::Run { args, parties, protocol, threshold, field, vm_opt } => {
            println!("▶️  Running project...");
            println!("   Parties: {}", parties);
            println!("   Protocol: {:?}", protocol);
            println!("   Field: {:?}", field);
            println!("   VM Optimization: {:?}", vm_opt);

            let threshold = threshold.unwrap_or_else(|| calculate_threshold(parties, &protocol));
            println!("   Threshold: {}", threshold);

            validate_mpc_params(parties, threshold, &protocol)?;

            if !args.is_empty() {
                println!("   Args: {:?}", args);
            }
            println!("   [TODO: Initialize StoffelVM with {:?} optimization]", vm_opt);
            println!("   [TODO: Setup {} MPC network with {} parties]", format!("{:?}", protocol).to_lowercase(), parties);
            println!("   [TODO: Execute program with args: {:?}]", args);
        }

        Commands::Deploy { environment, tee, k8s } => {
            println!("🚀 Deploying project...");
            println!("   Environment: {}", environment);
            if tee {
                println!("   TEE deployment enabled");
            }
            if k8s {
                println!("   Kubernetes deployment enabled");
            }
            println!("   [TODO: Implement deployment logic]");
        }

        Commands::Add { package, version, dev } => {
            println!("📦 Adding dependency: {}", package);
            if let Some(version) = version {
                println!("   Version: {}", version);
            }
            if dev {
                println!("   Type: Development dependency");
            }
            println!("   [TODO: Implement package management]");
        }

        Commands::Publish { dry_run } => {
            println!("📤 Publishing package...");
            if dry_run {
                println!("   Mode: Dry run");
            }
            println!("   [TODO: Implement publishing logic]");
        }

        Commands::Plugin { action } => {
            match action {
                PluginCommands::Install { name } => {
                    println!("🔌 Installing plugin: {}", name);
                    println!("   [TODO: Implement plugin installation]");
                }
                PluginCommands::List => {
                    println!("🔌 Installed plugins:");
                    println!("   [TODO: List installed plugins]");
                }
                PluginCommands::Remove { name } => {
                    println!("🔌 Removing plugin: {}", name);
                    println!("   [TODO: Implement plugin removal]");
                }
            }
        }

        Commands::Status => {
            println!("📊 Project Status:");
            println!("   [TODO: Check project configuration, dependencies, build status]");
        }

        Commands::Clean => {
            println!("🧹 Cleaning build artifacts...");
            println!("   [TODO: Implement clean logic]");
        }

        Commands::Update { package } => {
            if let Some(package) = package {
                println!("⬆️  Updating package: {}", package);
            } else {
                println!("⬆️  Updating all dependencies...");
            }
            println!("   [TODO: Implement dependency updates]");
        }
    }

    Ok(())
}

/// Find all .stfl files recursively in a directory
fn find_stfl_files(dir: &str) -> Result<Vec<String>, String> {
    let mut stfl_files = Vec::new();
    find_stfl_files_recursive(std::path::Path::new(dir), &mut stfl_files)?;
    stfl_files.sort(); // Sort for consistent ordering
    Ok(stfl_files)
}

/// Recursively find .stfl files in a directory
fn find_stfl_files_recursive(dir: &std::path::Path, files: &mut Vec<String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            // Recursively search subdirectories
            find_stfl_files_recursive(&path, files)?;
        } else if let Some(extension) = path.extension() {
            if extension == "stfl" {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }

    Ok(())
}

/// Compile a single StoffelLang file
fn compile_single_file(
    compiler_path: &std::path::Path,
    file: &str,
    output: &Option<String>,
    binary: bool,
    disassemble: bool,
    print_ir: bool,
    opt_level: u8,
) -> Result<bool, String> {
    // Build arguments for the Stoffel-Lang compiler
    let mut args = vec![file.to_string()];

    if let Some(output) = output {
        args.push("-o".to_string());
        args.push(output.clone());
    }

    if binary {
        args.push("--binary".to_string());
    }

    if disassemble {
        args.push("--disassemble".to_string());
    }

    if print_ir {
        args.push("--print-ir".to_string());
    }

    if opt_level > 0 {
        args.push(format!("-O{}", opt_level));
    }

    // Execute the Stoffel-Lang compiler
    let output = std::process::Command::new(compiler_path)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute compiler: {}", e))?;

    // Print compiler output
    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }

    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(output.status.success())
}

/// Calculate appropriate threshold based on number of parties and protocol
fn calculate_threshold(parties: u8, protocol: &MpcProtocol) -> u8 {
    match protocol {
        MpcProtocol::Honeybadger => {
            // HoneyBadger requires n >= 5 and t < n/3
            if parties < 5 {
                // Return a reasonable threshold anyway, validation will catch this
                return 1;
            }
            (parties - 1) / 3
        }
    }
}

/// Validate MPC parameters for the given protocol
fn validate_mpc_params(parties: u8, threshold: u8, protocol: &MpcProtocol) -> Result<(), String> {
    match protocol {
        MpcProtocol::Honeybadger => {
            if parties < 5 {
                return Err("HoneyBadger protocol requires at least 5 parties".to_string());
            }
            if threshold >= (parties + 2) / 3 {
                return Err(format!(
                    "HoneyBadger protocol requires threshold < n/3. For {} parties, max threshold is {}",
                    parties,
                    (parties + 2) / 3 - 1
                ));
            }
        }
    }

    Ok(())
} 