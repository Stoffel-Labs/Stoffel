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

fn show_template_help() {
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

    // Check for flag-specific help patterns like "stoffel init -t -h" or "stoffel init --template --help"
    if args.len() >= 4 {
        match (args.get(1).map(|s| s.as_str()), args.get(2).map(|s| s.as_str())) {
            (Some("init"), Some("-t" | "--template")) => {
                if args.get(3).map(|s| s.as_str()) == Some("-h") || args.get(3).map(|s| s.as_str()) == Some("--help") {
                    show_template_help();
                    return Ok(());
                }
            }
            _ => {}
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