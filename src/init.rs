use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
pub struct StoffelConfig {
    pub package: PackageConfig,
    pub mpc: MpcConfig,
    pub dependencies: Option<HashMap<String, String>>,
    pub dev_dependencies: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PackageConfig {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub authors: Option<Vec<String>>,
    pub license: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MpcConfig {
    pub protocol: String,
    pub parties: u8,
    pub threshold: Option<u8>,
    pub field: String,
}

pub struct InitOptions {
    pub name: Option<String>,
    pub lib: bool,
    pub path: Option<String>,
    pub interactive: bool,
    pub template: Option<String>,
}

pub fn initialize_project(options: InitOptions) -> Result<(), String> {
    let project_path = determine_project_path(&options)?;
    let project_name = determine_project_name(&options, &project_path)?;

    if options.interactive {
        initialize_interactive(project_name, project_path, options.lib)?;
    } else if let Some(template) = &options.template {
        initialize_from_template(project_name, project_path, template, options.lib)?;
    } else {
        initialize_default(project_name, project_path, options.lib)?;
    }

    Ok(())
}

fn determine_project_path(options: &InitOptions) -> Result<PathBuf, String> {
    let base_path = if let Some(path) = &options.path {
        PathBuf::from(path)
    } else {
        std::env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?
    };

    if let Some(name) = &options.name {
        Ok(base_path.join(name))
    } else {
        Ok(base_path)
    }
}

fn determine_project_name(options: &InitOptions, project_path: &Path) -> Result<String, String> {
    if let Some(name) = &options.name {
        Ok(name.clone())
    } else {
        project_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.to_string())
            .ok_or_else(|| "Could not determine project name".to_string())
    }
}

fn initialize_interactive(name: String, path: PathBuf, is_lib: bool) -> Result<(), String> {
    println!("🚀 Interactive Stoffel project setup");
    println!("Press Enter to use default values shown in [brackets]");
    println!();

    // Project details
    let project_name = prompt_with_default("Project name", &name)?;
    let description = prompt_optional("Description")?;
    let author = prompt_with_default("Author", &get_git_user().unwrap_or_else(|| "Unknown".to_string()))?;

    // MPC Configuration
    println!("\n🔒 MPC Configuration:");
    let parties = prompt_with_default_parsed("Number of parties", 5u8)?;
    let field = prompt_with_default("Field type", "bls12-381")?;

    // Validate parties for HoneyBadger
    if parties < 5 {
        return Err("HoneyBadger protocol requires at least 5 parties".to_string());
    }

    let threshold = (parties - 1) / 3;
    println!("   Calculated threshold: {} (max corrupted parties)", threshold);

    // Template selection based on programming language ecosystem
    let template = if !is_lib {
        println!("\n📋 Available language ecosystems:");
        println!("   1. python - Python SDK integration (fully implemented)");
        println!("   2. rust - Rust FFI integration (skeleton)");
        println!("   3. typescript - TypeScript/Node.js integration (skeleton)");
        println!("   4. solidity - Solidity smart contract integration (skeleton)");
        println!("   5. stoffel - Pure StoffelLang (default)");

        let choice = prompt_with_default("Choose ecosystem (1-5)", "5")?;
        match choice.as_str() {
            "1" => Some("python"),
            "2" => Some("rust"),
            "3" => Some("typescript"),
            "4" => Some("solidity"),
            _ => Some("stoffel"),
        }
    } else {
        None
    };

    println!("\n📁 Creating project structure...");

    let config = StoffelConfig {
        package: PackageConfig {
            name: project_name,
            version: "0.1.0".to_string(),
            description: if description.is_empty() { None } else { Some(description) },
            authors: Some(vec![author]),
            license: Some("MIT".to_string()),
        },
        mpc: MpcConfig {
            protocol: "honeybadger".to_string(),
            parties,
            threshold: Some(threshold),
            field,
        },
        dependencies: None,
        dev_dependencies: None,
    };

    create_project_structure(&path, &config, is_lib, template)?;
    println!("✅ Project initialized successfully at {}", path.display());
    Ok(())
}

fn initialize_from_template(name: String, path: PathBuf, template: &str, is_lib: bool) -> Result<(), String> {
    println!("🚀 Initializing from template: {}", template);

    let config = StoffelConfig {
        package: PackageConfig {
            name,
            version: "0.1.0".to_string(),
            description: Some(get_template_description(template)),
            authors: Some(vec![get_git_user().unwrap_or_else(|| "Unknown".to_string())]),
            license: Some("MIT".to_string()),
        },
        mpc: MpcConfig {
            protocol: "honeybadger".to_string(),
            parties: 5,
            threshold: Some(1),
            field: "bls12-381".to_string(),
        },
        dependencies: None,
        dev_dependencies: None,
    };

    create_project_structure(&path, &config, is_lib, Some(template))?;
    println!("✅ Project initialized successfully at {}", path.display());
    Ok(())
}

fn initialize_default(name: String, path: PathBuf, is_lib: bool) -> Result<(), String> {
    println!("🚀 Initializing default Stoffel project");

    let config = StoffelConfig {
        package: PackageConfig {
            name,
            version: "0.1.0".to_string(),
            description: Some("A Stoffel MPC application".to_string()),
            authors: Some(vec![get_git_user().unwrap_or_else(|| "Unknown".to_string())]),
            license: Some("MIT".to_string()),
        },
        mpc: MpcConfig {
            protocol: "honeybadger".to_string(),
            parties: 5,
            threshold: Some(1),
            field: "bls12-381".to_string(),
        },
        dependencies: None,
        dev_dependencies: None,
    };

    create_project_structure(&path, &config, is_lib, Some("basic"))?;
    println!("✅ Project initialized successfully at {}", path.display());
    Ok(())
}

fn create_project_structure(
    path: &Path,
    config: &StoffelConfig,
    is_lib: bool,
    template: Option<&str>,
) -> Result<(), String> {
    // Create main directory
    fs::create_dir_all(path)
        .map_err(|e| format!("Failed to create project directory: {}", e))?;

    // Create Stoffel.toml
    let toml_content = toml::to_string(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(path.join("Stoffel.toml"), toml_content)
        .map_err(|e| format!("Failed to write Stoffel.toml: {}", e))?;

    if is_lib {
        create_library_structure(path, config, template)?;
    } else {
        create_project_structure_full(path, config, template)?;
    }

    Ok(())
}

fn create_project_structure_full(path: &Path, config: &StoffelConfig, template: Option<&str>) -> Result<(), String> {
    let template = template.unwrap_or("stoffel");

    match template {
        "python" => create_python_project(path, config)?,
        "rust" => create_rust_project(path, config)?,
        "typescript" => create_typescript_project(path, config)?,
        "solidity" => create_solidity_project(path, config)?,
        _ => create_stoffel_project(path, config)?,
    }

    // Create README for all templates
    let readme_content = get_template_readme(config, template);
    fs::write(path.join("README.md"), readme_content)
        .map_err(|e| format!("Failed to write README.md: {}", e))?;

    Ok(())
}

fn create_library_structure(path: &Path, config: &StoffelConfig, _template: Option<&str>) -> Result<(), String> {
    // Create lib structure
    fs::create_dir_all(path.join("src")).map_err(|e| format!("Failed to create src directory: {}", e))?;

    // Create lib.stfl
    let lib_content = r#"// Stoffel Library
// This library provides privacy-preserving computation functions

// Example function for secure computation
fn secure_add(a: SecretInt, b: SecretInt) -> SecretInt {
    return a + b;
}

// Export main functions
export { secure_add };
"#;
    fs::write(path.join("src").join("lib.stfl"), lib_content)
        .map_err(|e| format!("Failed to write lib.stfl: {}", e))?;

    // Create README for library
    let readme_content = format!(r#"# {}

A Stoffel MPC library for privacy-preserving computation.

## Installation

```bash
stoffel add {}
```

## Usage

```stoffel
import {{ secure_add }} from "{}";

let result = secure_add(secret_a, secret_b);
```

## Configuration

- Protocol: {}
- Parties: {}
- Field: {}
"#,
        config.package.name,
        config.package.name,
        config.package.name,
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field
    );

    fs::write(path.join("README.md"), readme_content)
        .map_err(|e| format!("Failed to write README.md: {}", e))?;

    Ok(())
}

// Template loading helper using embedded templates
fn load_template(template_name: &str, file_name: &str) -> Result<String, String> {
    match (template_name, file_name) {
        ("python", "main.py") => Ok(include_str!("templates/python/main.py").to_string()),
        ("python", "pyproject.toml") => Ok(include_str!("templates/python/pyproject.toml").to_string()),
        ("python", "secure_computation.stfl") => Ok(include_str!("templates/python/secure_computation.stfl").to_string()),
        ("python", "test_main.py") => Ok(include_str!("templates/python/test_main.py").to_string()),
        _ => Err(format!("Template file not found: {}/{}", template_name, file_name))
    }
}

fn substitute_template_vars(template_content: &str, config: &StoffelConfig) -> String {
    template_content
        .replace("{{package_name}}", &config.package.name)
        .replace("{{package_version}}", &config.package.version)
        .replace("{{package_description}}", config.package.description.as_deref().unwrap_or("Stoffel MPC application"))
        .replace("{{package_authors}}", &config.package.authors.as_ref()
            .map(|authors| authors.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(", "))
            .unwrap_or_else(|| "\"Unknown\"".to_string()))
        .replace("{{package_name_underscore}}", &config.package.name.replace("-", "_"))
        .replace("{{mpc_protocol}}", &config.mpc.protocol)
        .replace("{{mpc_parties}}", &config.mpc.parties.to_string())
        .replace("{{mpc_field}}", &config.mpc.field)
}

// Language-specific project creators
fn create_python_project(path: &Path, config: &StoffelConfig) -> Result<(), String> {
    // Create Python project structure
    fs::create_dir_all(path.join("src")).map_err(|e| format!("Failed to create src directory: {}", e))?;
    fs::create_dir_all(path.join("tests")).map_err(|e| format!("Failed to create tests directory: {}", e))?;

    // Create pyproject.toml
    let pyproject_template = load_template("python", "pyproject.toml")?;
    let pyproject_content = substitute_template_vars(&pyproject_template, config);
    fs::write(path.join("pyproject.toml"), pyproject_content)
        .map_err(|e| format!("Failed to write pyproject.toml: {}", e))?;

    // Create main Python file with actual SDK integration
    let main_py_template = load_template("python", "main.py")?;
    let main_py_content = substitute_template_vars(&main_py_template, config);
    fs::write(path.join("src").join("main.py"), main_py_content)
        .map_err(|e| format!("Failed to write main.py: {}", e))?;

    // Create StoffelLang program file
    let stfl_template = load_template("python", "secure_computation.stfl")?;
    let stfl_content = substitute_template_vars(&stfl_template, config);
    fs::write(path.join("src").join("secure_computation.stfl"), stfl_content)
        .map_err(|e| format!("Failed to write secure_computation.stfl: {}", e))?;

    // Create test file
    let test_template = load_template("python", "test_main.py")?;
    let test_content = substitute_template_vars(&test_template, config);
    fs::write(path.join("tests").join("test_main.py"), test_content)
        .map_err(|e| format!("Failed to write test file: {}", e))?;

    Ok(())
}

fn create_rust_project(path: &Path, config: &StoffelConfig) -> Result<(), String> {
    // Create Rust project structure
    fs::create_dir_all(path.join("src")).map_err(|e| format!("Failed to create src directory: {}", e))?;

    // Create Cargo.toml
    let cargo_content = format!(r#"[package]
name = "{}"
version = "{}"
edition = "2021"
authors = [{}]
description = "{}"

[dependencies]
# FFI bindings to StoffelVM
libc = "0.2"
# stoffel-vm-types = {{ path = "../StoffelVM/crates/stoffel-vm-types" }}
# stoffel-vm = {{ path = "../StoffelVM/crates/stoffel-vm" }}

[dev-dependencies]
tokio = {{ version = "1.0", features = ["full"] }}
"#,
        config.package.name,
        config.package.version,
        config.package.authors.as_ref()
            .map(|authors| authors.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(", "))
            .unwrap_or_else(|| "\"Unknown\"".to_string()),
        config.package.description.as_deref().unwrap_or("Stoffel MPC application")
    );

    fs::write(path.join("Cargo.toml"), cargo_content)
        .map_err(|e| format!("Failed to write Cargo.toml: {}", e))?;

    // Create main.rs with FFI skeleton - simplified version
    let main_rs_content = format!(r#"//! {} - {}
//! Generated by Stoffel CLI
//!
//! Rust FFI integration with StoffelVM for MPC computation
//! Protocol: {}, Parties: {}, Field: {}

// TODO: Uncomment when StoffelVM crates are available
// use stoffel_vm::core_vm::VirtualMachine;
// use stoffel_vm::functions::VMFunction;
// use stoffel_vm::instructions::Instruction;
// use stoffel_vm::core_types::Value;
use std::collections::HashMap;

/// Main MPC computation using Rust FFI to StoffelVM
fn main() -> Result<(), String> {{
    println!("=== Stoffel Rust MPC Demo ===");
    println!("Protocol: honeybadger");
    println!("Parties: {}", {});
    println!("Field: bls12-381");

    // TODO: Implement StoffelVM integration
    println!("Rust FFI integration with StoffelVM coming soon!");

    Ok(())
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_basic() {{
        assert!(main().is_ok());
    }}
}}
"#,
        config.package.name,
        config.package.description.as_deref().unwrap_or("Stoffel MPC application"),
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field,
        config.mpc.parties,
        config.mpc.parties
    );

    fs::write(path.join("src").join("main.rs"), main_rs_content)
        .map_err(|e| format!("Failed to write main.rs: {}", e))?;

    Ok(())
}

fn create_typescript_project(path: &Path, config: &StoffelConfig) -> Result<(), String> {
    // Create TypeScript project structure
    fs::create_dir_all(path.join("src")).map_err(|e| format!("Failed to create src directory: {}", e))?;

    // Create package.json
    let package_json = format!(r#"{{
  "name": "{}",
  "version": "{}",
  "description": "{}",
  "main": "dist/main.js",
  "scripts": {{
    "build": "tsc",
    "start": "node dist/main.js",
    "dev": "ts-node src/main.ts",
    "test": "jest"
  }},
  "dependencies": {{
    "@stoffel/sdk": "file:../stoffel-typescript-sdk"
  }},
  "devDependencies": {{
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "ts-node": "^10.9.0",
    "jest": "^29.0.0",
    "@types/jest": "^29.0.0"
  }},
  "keywords": ["mpc", "privacy", "secure-computation", "stoffel"],
  "author": "{}",
  "license": "MIT"
}}
"#,
        config.package.name,
        config.package.version,
        config.package.description.as_deref().unwrap_or("Stoffel MPC application"),
        config.package.authors.as_ref().and_then(|a| a.first()).unwrap_or(&"Unknown".to_string())
    );

    fs::write(path.join("package.json"), package_json)
        .map_err(|e| format!("Failed to write package.json: {}", e))?;

    // Create tsconfig.json
    let tsconfig = r#"{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  }
}
"#;
    fs::write(path.join("tsconfig.json"), tsconfig)
        .map_err(|e| format!("Failed to write tsconfig.json: {}", e))?;

    // Create main.ts with SDK skeleton
    let main_ts_content = format!(r#"/**
 * {} - {}
 * Generated by Stoffel CLI
 *
 * TypeScript/Node.js integration with Stoffel MPC framework
 * Protocol: {}, Parties: {}, Field: {}
 */

// TODO: Import actual Stoffel TypeScript SDK when available
// import {{ StoffelClient, StoffelProgram }} from '@stoffel/sdk';

interface StoffelConfig {{
    nodes: string[];
    clientId: string;
    programId: string;
    protocol: string;
    parties: number;
    field: string;
}}

interface SecretInputs {{
    [key: string]: number | string | boolean;
}}

interface PublicInputs {{
    [key: string]: number | string | boolean;
}}

/**
 * Stoffel MPC Client (Skeleton Implementation)
 * TODO: Replace with actual SDK import
 */
class StoffelClient {{
    private config: StoffelConfig;
    private connected: boolean = false;

    constructor(config: StoffelConfig) {{
        this.config = config;
        console.log(`Initialized Stoffel client for ${{config.parties}} parties`);
    }}

    async connect(): Promise<void> {{
        console.log('Connecting to MPC network...');
        // TODO: Implement actual connection logic
        this.connected = true;
        console.log('✓ Connected to MPC network');
    }}

    async executeWithInputs(
        secretInputs: SecretInputs,
        publicInputs?: PublicInputs
    ): Promise<any> {{
        console.log('🔒 Executing secure computation...');
        console.log(`Secret inputs: ${{Object.keys(secretInputs).length}} values`);
        if (publicInputs) {{
            console.log(`Public inputs: ${{Object.keys(publicInputs).length}} values`);
        }}

        // TODO: Implement actual MPC execution
        // For now, return mock result
        return {{
            result: 67, // Mock computation result
            protocol: this.config.protocol,
            parties: this.config.parties
        }};
    }}

    async disconnect(): Promise<void> {{
        console.log('Disconnecting from MPC network...');
        this.connected = false;
        console.log('✓ Disconnected');
    }}

    isConnected(): boolean {{
        return this.connected;
    }}
}}

/**
 * Main MPC demonstration
 */
async function main(): Promise<void> {{
    console.log('=== Stoffel TypeScript MPC Demo ===\\n');

    // 1. Configure MPC client
    console.log('1. Setting up MPC client...');
    const client = new StoffelClient({{
        nodes: [
            'http://localhost:9001',
            'http://localhost:9002',
            'http://localhost:9003',
            'http://localhost:9004',
            'http://localhost:9005'
        ],
        clientId: '{}',
        programId: 'secure_computation',
        protocol: '{}',
        parties: {},
        field: '{}'
    }});

    // 2. Connect to MPC network
    await client.connect();

    // 3. Execute secure computation
    console.log('\\n2. Executing secure computation...');
    const result = await client.executeWithInputs(
        {{
            secretValue1: 42,
            secretValue2: 25
        }},
        {{
            threshold: 50,
            operation: 'add'
        }}
    );

    console.log(`📊 Computation result: ${{result.result}}`);
    console.log(`Protocol: ${{result.protocol}}, Parties: ${{result.parties}}`);

    // 4. Healthcare analytics example
    await healthcareAnalyticsExample(client);

    // 5. Clean up
    await client.disconnect();
    console.log('\\n=== Demo Complete ===');
}}

/**
 * Example: Privacy-preserving healthcare analytics
 */
async function healthcareAnalyticsExample(client: StoffelClient): Promise<void> {{
    console.log('\\n3. Healthcare Analytics Example...');

    const result = await client.executeWithInputs(
        {{
            patientAges: [25, 34, 45, 67, 23, 56],
            conditions: [0, 1, 0, 1, 0, 1]
        }},
        {{
            analysisType: 'prevalence_study',
            minAge: 18,
            maxAge: 80
        }}
    );

    console.log('📈 Healthcare analytics (privacy-preserving):');
    console.log('   Individual patient data remains private');
    console.log(`   Aggregate statistics: ${{result.result}}`);
}}

/**
 * Financial risk assessment example
 */
async function financialRiskExample(): Promise<void> {{
    console.log('\\n=== Financial Risk Assessment ===');

    const client = new StoffelClient({{
        nodes: ['http://localhost:9001', 'http://localhost:9002', 'http://localhost:9003',
                'http://localhost:9004', 'http://localhost:9005'],
        clientId: 'financial_client',
        programId: 'risk_assessment',
        protocol: '{}',
        parties: {},
        field: '{}'
    }});

    await client.connect();

    const result = await client.executeWithInputs(
        {{
            portfolioValues: [100000, 250000, 75000],
            riskFactors: [0.1, 0.05, 0.15]
        }},
        {{
            marketCondition: 'volatile',
            regulatoryFactor: 1.2
        }}
    );

    console.log(`💰 Risk assessment: ${{result.result}}`);
    await client.disconnect();
}}

// Run the examples
if (require.main === module) {{
    main().catch(console.error);
}}

export {{ StoffelClient, main, healthcareAnalyticsExample, financialRiskExample }};
"#,
        config.package.name,
        config.package.description.as_deref().unwrap_or("Stoffel MPC application"),
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field,
        config.package.name.replace("-", "_"),
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field,
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field
    );

    fs::write(path.join("src").join("main.ts"), main_ts_content)
        .map_err(|e| format!("Failed to write main.ts: {}", e))?;

    Ok(())
}

fn create_solidity_project(path: &Path, config: &StoffelConfig) -> Result<(), String> {
    // Create Solidity project structure
    fs::create_dir_all(path.join("contracts")).map_err(|e| format!("Failed to create contracts directory: {}", e))?;
    fs::create_dir_all(path.join("scripts")).map_err(|e| format!("Failed to create scripts directory: {}", e))?;
    fs::create_dir_all(path.join("test")).map_err(|e| format!("Failed to create test directory: {}", e))?;

    // Create hardhat.config.js
    let hardhat_config = r#"require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.20",
  networks: {
    hardhat: {},
    // Add Stoffel MPC network configuration here
    stoffel: {
      url: "http://localhost:8545",
      accounts: []
    }
  }
};
"#;
    fs::write(path.join("hardhat.config.js"), hardhat_config)
        .map_err(|e| format!("Failed to write hardhat.config.js: {}", e))?;

    // Create package.json for Solidity project
    let package_json = format!(r#"{{
  "name": "{}",
  "version": "{}",
  "description": "{}",
  "scripts": {{
    "compile": "hardhat compile",
    "test": "hardhat test",
    "deploy": "hardhat run scripts/deploy.js"
  }},
  "devDependencies": {{
    "@nomicfoundation/hardhat-toolbox": "^3.0.0",
    "hardhat": "^2.17.0"
  }},
  "keywords": ["solidity", "mpc", "privacy", "smart-contracts", "stoffel"]
}}
"#,
        config.package.name,
        config.package.version,
        config.package.description.as_deref().unwrap_or("Stoffel MPC smart contract")
    );

    fs::write(path.join("package.json"), package_json)
        .map_err(|e| format!("Failed to write package.json: {}", e))?;

    // Create main Solidity contract
    let contract_content = format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * {} - {}
 * Generated by Stoffel CLI
 *
 * Solidity smart contract with MPC integration
 * Protocol: {}, Parties: {}, Field: {}
 */

/// @title StoffelMPC
/// @dev Smart contract interface for Stoffel MPC computations
/// @notice This contract provides on-chain verification of MPC results
contract StoffelMPC {{

    struct MPCConfig {{
        string protocol;
        uint8 parties;
        uint8 threshold;
        string field;
    }}

    struct ComputationResult {{
        bytes32 commitmentHash;
        uint256 result;
        uint256 timestamp;
        bool verified;
    }}

    MPCConfig public mpcConfig;
    mapping(bytes32 => ComputationResult) public computationResults;
    mapping(address => bool) public authorizedNodes;

    event ComputationSubmitted(bytes32 indexed computationId, uint256 result);
    event ComputationVerified(bytes32 indexed computationId, bool success);
    event NodeAuthorized(address indexed node);

    modifier onlyAuthorizedNode() {{
        require(authorizedNodes[msg.sender], "Only authorized MPC nodes can submit results");
        _;
    }}

    constructor() {{
        mpcConfig = MPCConfig({{
            protocol: "{}",
            parties: {},
            threshold: {},
            field: "{}"
        }});

        // TODO: Initialize with actual MPC node addresses
        // For now, authorize the deployer
        authorizedNodes[msg.sender] = true;
    }}

    /// @notice Submit MPC computation result with proof
    /// @param computationId Unique identifier for the computation
    /// @param result The computed result from MPC
    /// @param proof Zero-knowledge proof of correct computation (placeholder)
    function submitMPCResult(
        bytes32 computationId,
        uint256 result,
        bytes calldata proof
    ) external onlyAuthorizedNode {{
        require(computationResults[computationId].timestamp == 0, "Computation already exists");

        // TODO: Verify the MPC proof
        bool isValid = verifyMPCProof(result, proof);

        computationResults[computationId] = ComputationResult({{
            commitmentHash: keccak256(abi.encodePacked(result, proof)),
            result: result,
            timestamp: block.timestamp,
            verified: isValid
        }});

        emit ComputationSubmitted(computationId, result);

        if (isValid) {{
            emit ComputationVerified(computationId, true);
        }}
    }}

    /// @notice Verify MPC computation proof (placeholder implementation)
    /// @param result The computation result
    /// @param proof The zero-knowledge proof
    /// @return bool Whether the proof is valid
    function verifyMPCProof(uint256 result, bytes calldata proof) internal pure returns (bool) {{
        // TODO: Implement actual proof verification
        // For now, basic sanity check
        return proof.length > 0 && result > 0;
    }}

    /// @notice Get computation result if verified
    /// @param computationId The computation identifier
    /// @return result The verified computation result
    function getVerifiedResult(bytes32 computationId) external view returns (uint256) {{
        ComputationResult memory comp = computationResults[computationId];
        require(comp.verified, "Computation not verified");
        return comp.result;
    }}

    /// @notice Authorize MPC node to submit results
    /// @param node Address of the MPC node
    function authorizeNode(address node) external {{
        // TODO: Add proper access control (e.g., Ownable)
        authorizedNodes[node] = true;
        emit NodeAuthorized(node);
    }}

    /// @notice Healthcare analytics with privacy preservation
    /// @param commitmentHash Hash commitment to private patient data
    /// @param aggregateResult Computed aggregate statistics (no individual data)
    function submitHealthcareAnalytics(
        bytes32 commitmentHash,
        uint256 aggregateResult
    ) external onlyAuthorizedNode {{
        bytes32 computationId = keccak256(abi.encodePacked("healthcare", block.timestamp));

        computationResults[computationId] = ComputationResult({{
            commitmentHash: commitmentHash,
            result: aggregateResult,
            timestamp: block.timestamp,
            verified: true  // Assume verified for this example
        }});

        emit ComputationSubmitted(computationId, aggregateResult);
    }}

    /// @notice Financial risk assessment with MPC
    /// @param riskScore Aggregate risk score (no individual portfolio data revealed)
    function submitRiskAssessment(uint256 riskScore) external onlyAuthorizedNode {{
        bytes32 computationId = keccak256(abi.encodePacked("risk", block.timestamp));

        computationResults[computationId] = ComputationResult({{
            commitmentHash: keccak256(abi.encodePacked(riskScore, msg.sender)),
            result: riskScore,
            timestamp: block.timestamp,
            verified: true
        }});

        emit ComputationSubmitted(computationId, riskScore);
    }}
}}

/// @title Private Auction Contract
/// @dev Demonstrates MPC integration for private auctions
contract PrivateAuction {{
    struct Auction {{
        bytes32 auctionId;
        uint256 startTime;
        uint256 endTime;
        uint256 winningBid;
        address winner;
        bool finalized;
    }}

    mapping(bytes32 => Auction) public auctions;
    mapping(bytes32 => mapping(address => bytes32)) public bidCommitments;

    event AuctionCreated(bytes32 indexed auctionId);
    event BidCommitted(bytes32 indexed auctionId, address bidder);
    event AuctionFinalized(bytes32 indexed auctionId, address winner, uint256 winningBid);

    /// @notice Commit to a sealed bid (commitment phase)
    function commitBid(bytes32 auctionId, bytes32 commitment) external {{
        require(block.timestamp < auctions[auctionId].endTime, "Auction ended");
        bidCommitments[auctionId][msg.sender] = commitment;
        emit BidCommitted(auctionId, msg.sender);
    }}

    /// @notice Finalize auction with MPC-computed winner
    /// @param auctionId The auction identifier
    /// @param winner Address of the winning bidder
    /// @param winningBid The winning bid amount (revealed via MPC)
    function finalizeAuction(
        bytes32 auctionId,
        address winner,
        uint256 winningBid
    ) external {{
        Auction storage auction = auctions[auctionId];
        require(block.timestamp >= auction.endTime, "Auction still active");
        require(!auction.finalized, "Already finalized");

        // TODO: Verify MPC proof that winner has highest bid
        // For now, trust the MPC computation result

        auction.winner = winner;
        auction.winningBid = winningBid;
        auction.finalized = true;

        emit AuctionFinalized(auctionId, winner, winningBid);
    }}
}}
"#,
        config.package.name,
        config.package.description.as_deref().unwrap_or("Stoffel MPC smart contract"),
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field,
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.threshold.unwrap_or(1),
        config.mpc.field
    );

    fs::write(path.join("contracts").join("StoffelMPC.sol"), contract_content)
        .map_err(|e| format!("Failed to write StoffelMPC.sol: {}", e))?;

    // Create deployment script
    let deploy_script = r#"// Deploy script for Stoffel MPC contracts
const hre = require("hardhat");

async function main() {
  console.log("Deploying Stoffel MPC contracts...");

  const StoffelMPC = await hre.ethers.getContractFactory("StoffelMPC");
  const stoffelMPC = await StoffelMPC.deploy();

  await stoffelMPC.deployed();
  console.log("StoffelMPC deployed to:", stoffelMPC.address);

  const PrivateAuction = await hre.ethers.getContractFactory("PrivateAuction");
  const privateAuction = await PrivateAuction.deploy();

  await privateAuction.deployed();
  console.log("PrivateAuction deployed to:", privateAuction.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
"#;

    fs::write(path.join("scripts").join("deploy.js"), deploy_script)
        .map_err(|e| format!("Failed to write deploy.js: {}", e))?;

    Ok(())
}

fn create_stoffel_project(path: &Path, config: &StoffelConfig) -> Result<(), String> {
    // Create directories
    fs::create_dir_all(path.join("src")).map_err(|e| format!("Failed to create src directory: {}", e))?;
    fs::create_dir_all(path.join("tests")).map_err(|e| format!("Failed to create tests directory: {}", e))?;

    // Create main.stfl (Pure StoffelLang)
    let main_content = format!(r#"# {} - {}
# Generated by Stoffel CLI
# Protocol: {}, Parties: {}, Field: {}
#
# TODO: Update this example when StoffelLang frontend has stabilized
# Current syntax is based on test files and may change

# Demonstration of StoffelLang MPC features
proc secure_computation(x: secret int64, y: secret int64): secret int64 =
  # Secret arithmetic operations
  let sum = x + y
  let difference = x - y
  let product = x * y

  # Mix of public and secret computations
  let public_factor: int64 = 3
  let scaled_sum = sum * public_factor

  # Return a combination result
  return scaled_sum + product

# Main entry point
proc main() =
  print("StoffelLang MPC Demo")

  # Get secret inputs from parties
  let input_a: secret int64 = get_input(0)
  let input_b: secret int64 = get_input(1)

  # Perform secure computation
  let result = secure_computation(input_a, input_b)

  print("Computation finished")
  return result
"#,
        config.package.name,
        config.package.description.as_deref().unwrap_or("Stoffel MPC application"),
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field
    );

    fs::write(path.join("src").join("main.stfl"), main_content)
        .map_err(|e| format!("Failed to write main.stfl: {}", e))?;

    // Create test file
    let test_content = r#"# Integration tests for StoffelLang MPC
#
# TODO: Update this example when StoffelLang frontend has stabilized
# Current syntax is based on test files and may change

# Test the secure computation function
proc test_secure_computation() =
  let x: secret int64 = 10
  let y: secret int64 = 5
  let result = secure_computation(x, y)
  print("Secure computation test completed")

# Test with different values
proc test_computation_variants() =
  let a: secret int64 = 20
  let b: secret int64 = 3
  let output = secure_computation(a, b)
  print("Computation variant test completed")

# Run all tests
proc run_tests() =
  print("Starting StoffelLang tests")
  test_secure_computation()
  test_computation_variants()
  print("All tests completed")
"#;

    fs::write(path.join("tests").join("integration.stfl"), test_content)
        .map_err(|e| format!("Failed to write test file: {}", e))?;

    Ok(())
}

// Helper functions
fn prompt_with_default(prompt: &str, default: &str) -> Result<String, String> {
    print!("{} [{}]: ", prompt, default);
    io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("IO error: {}", e))?;

    let input = input.trim();
    Ok(if input.is_empty() { default.to_string() } else { input.to_string() })
}

fn prompt_optional(prompt: &str) -> Result<String, String> {
    print!("{}: ", prompt);
    io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("IO error: {}", e))?;

    Ok(input.trim().to_string())
}

fn prompt_with_default_parsed<T: std::str::FromStr>(prompt: &str, default: T) -> Result<T, String>
where
    T: std::fmt::Display + Copy,
    T::Err: std::fmt::Display,
{
    let response = prompt_with_default(prompt, &default.to_string())?;
    response.parse().map_err(|e| format!("Invalid input: {}", e))
}

fn get_git_user() -> Option<String> {
    std::process::Command::new("git")
        .args(&["config", "user.name"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

fn get_template_description(template: &str) -> String {
    match template {
        "python" => "Python SDK integration for MPC applications".to_string(),
        "rust" => "Rust FFI integration with StoffelVM".to_string(),
        "typescript" => "TypeScript/Node.js MPC integration".to_string(),
        "solidity" => "Solidity smart contract with MPC integration".to_string(),
        _ => "A Stoffel MPC application".to_string(),
    }
}


fn get_template_readme(config: &StoffelConfig, template: &str) -> String {
    let (quickstart, additional_info) = match template {
        "python" => (
            r#"```bash
# Install dependencies
poetry install

# Run the MPC demo
poetry run python src/main.py

# Run tests
poetry run pytest

# Development with the Python SDK
poetry run python src/main.py
```"#,
            r#"## Python SDK Integration

This project uses the Stoffel Python SDK for MPC operations:

- **StoffelProgram**: Handles StoffelLang compilation and VM operations
- **StoffelClient**: Manages MPC network communication and secret sharing
- **Async/Await**: Full async support for non-blocking MPC operations

## Dependencies

- Python 3.8+
- Poetry for dependency management
- Stoffel Python SDK (local development path)

## Examples

The project includes examples for:
- Basic secure addition
- Healthcare analytics (privacy-preserving)
- Financial risk assessment"#
        ),
        "rust" => (
            r#"```bash
# Build the project
cargo build

# Run the MPC demo
cargo run

# Run tests
cargo test

# Development mode
cargo run --dev
```"#,
            r#"## Rust FFI Integration

This project uses direct FFI integration with StoffelVM:

- **Direct VM Access**: Low-level control over StoffelVM operations
- **Performance**: Minimal overhead for MPC computations
- **Type Safety**: Rust's type system ensures memory safety

## Dependencies

- Rust 2021 edition
- StoffelVM crates (local workspace)
- Tokio for async operations"#
        ),
        "typescript" => (
            r#"```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run the MPC demo
npm run start

# Development mode
npm run dev

# Run tests
npm test
```"#,
            r#"## TypeScript SDK Integration

This project provides a TypeScript interface to Stoffel MPC:

- **Type Safety**: Full TypeScript definitions for MPC operations
- **Modern JavaScript**: ES2020+ features with async/await
- **Node.js**: Server-side MPC client implementation

## Dependencies

- Node.js 18+
- TypeScript 5.0+
- Stoffel TypeScript SDK (when available)

Note: This template currently contains skeleton code. Full TypeScript SDK implementation is in progress."#
        ),
        "solidity" => (
            r#"```bash
# Install dependencies
npm install

# Compile contracts
npm run compile

# Deploy contracts
npm run deploy

# Run tests
npm test
```"#,
            r#"## Solidity Smart Contract Integration

This project provides on-chain verification of MPC computations:

- **MPC Result Verification**: Smart contracts verify MPC computation results
- **Zero-Knowledge Proofs**: Support for ZK proofs of correct computation
- **Private Auctions**: Example implementation of private auction mechanisms
- **Healthcare Analytics**: On-chain verification of privacy-preserving statistics

## Smart Contracts

- **StoffelMPC.sol**: Main contract for MPC result verification
- **PrivateAuction.sol**: Private auction implementation

## Dependencies

- Hardhat development environment
- Solidity 0.8.20
- OpenZeppelin contracts"#
        ),
        _ => (
            r#"```bash
# Run the application
stoffel run

# Development mode with hot reloading
stoffel dev

# Run tests
stoffel test

# Build optimized version
stoffel build --release
```"#,
            r#"## StoffelLang Implementation

This project uses pure StoffelLang for MPC computations:

- **Native MPC**: Built-in secret sharing and secure computation
- **Type Safety**: Strong typing with SecretInt and PublicInt
- **Performance**: Optimized for the StoffelVM execution environment

## StoffelLang Features

- Secret integer types with automatic MPC operations
- Built-in functions for secure computation (add, multiply, reveal)
- Support for complex data structures (vectors, structs)
- Privacy-preserving algorithms"#
        )
    };

    format!(r#"# {}

{}

## Quick Start

{}

## Configuration

- **Protocol**: {} (HoneyBadger MPC)
- **Parties**: {} (minimum 5 for HoneyBadger)
- **Field**: {} (cryptographic field)
- **Threshold**: {} (max corrupted parties)

## Language Ecosystem

This project was generated for the **{}** ecosystem.

{}

## MPC Features

This application demonstrates:

- **Secure Computation**: Private inputs from multiple parties
- **Privacy Preservation**: Individual data never revealed
- **Result Reconstruction**: Only final results are disclosed
- **Healthcare Analytics**: Privacy-preserving medical statistics
- **Financial Risk**: Confidential portfolio risk assessment

## Learn More

- [Stoffel Documentation](https://docs.stoffel.dev)
- [MPC Introduction](https://docs.stoffel.dev/mpc-intro)
- [HoneyBadger Protocol](https://docs.stoffel.dev/honeybadger)
- [StoffelLang Guide](https://docs.stoffel.dev/language)
- [Python SDK](https://docs.stoffel.dev/python-sdk)
"#,
        config.package.name,
        config.package.description.as_deref().unwrap_or("A Stoffel MPC application"),
        quickstart,
        config.mpc.protocol,
        config.mpc.parties,
        config.mpc.field,
        config.mpc.threshold.unwrap_or(1),
        template,
        additional_info
    )
}