use clap::{Parser, Subcommand, ValueEnum};

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
    Init {
        /// Project name
        name: Option<String>,

        /// Initialize as a library instead of standalone project
        #[arg(long)]
        lib: bool,

        /// Path to initialize in
        #[arg(long)]
        path: Option<String>,

        /// Use interactive mode for setup
        #[arg(short, long)]
        interactive: bool,

        /// Template to use for initialization
        #[arg(short, long)]
        template: Option<String>,
    },

    /// Start development server with hot reloading
    Dev {
        /// Number of parties for simulation (minimum 5 for HoneyBadger)
        #[arg(long, default_value = "5")]
        parties: u8,

        /// Port to run on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// MPC protocol to use
        #[arg(long, default_value = "honeybadger")]
        protocol: MpcProtocol,

        /// Security threshold (max corrupted parties, auto-calculated if not provided)
        #[arg(long)]
        threshold: Option<u8>,

        /// Field type for computation
        #[arg(long, default_value = "bls12-381")]
        field: MpcField,
    },

    /// Build the current project
    Build {
        /// Target to build for
        #[arg(long)]
        target: Option<String>,

        /// Enable optimizations
        #[arg(long)]
        optimize: bool,

        /// Release build
        #[arg(short, long)]
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
            println!("🚀 Initializing Stoffel project...");
            if lib {
                println!("   Mode: Library");
            } else {
                println!("   Mode: Standalone project");
            }
            if let Some(template) = template {
                println!("   Template: {}", template);
            }
            if let Some(path) = path {
                println!("   Path: {}", path);
            }
            if let Some(name) = name {
                println!("   Name: {}", name);
            }
            if interactive {
                println!("   Interactive setup enabled");
            }
            println!("   [TODO: Implement initialization logic]");
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