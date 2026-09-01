use std::fs;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use jsonrpsee::{core::RpcResult, server::RpcModule};
use stoffel_mpc_coordinator_off_chain::{
    ClientIdentity, CoordinatorRPCBaseServer, CoordinatorRPCServerConnectionBase,
    CoordinatorRPCServerSharedBase, ExecutionRegistration, InputAssignment,
    OffChainCoordinatorServer, StoffelCoordinatorRPCServer,
};
use stoffel_mpc_coordinator_shared::rpc::RPCServerConnection;
use stoffel_mpc_coordinator_shared::{ExecutionId, Round};
use tokio::sync::Mutex;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "Run one long-lived off-chain coordinator. Executions are registered dynamically \
or optionally pre-registered with --execution-id."
)]
struct Args {
    #[arg(long, requires = "execution_id")]
    hash: Option<String>,

    #[arg(long, value_parser = parse_nonzero_execution_id)]
    execution_id: Option<ExecutionId>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    initial_mpc_nodes: Vec<String>,

    #[arg(long)]
    server_cert: String,

    #[arg(long)]
    server_key: String,

    #[arg(long)]
    n: u64,

    #[arg(long)]
    t: u64,

    #[arg(long, default_value_t = 0)]
    n_inputs: u64,

    #[arg(long, value_delimiter = ',', num_args = 0..)]
    output_clients: Vec<String>,

    #[arg(long, default_value = "honeybadger")]
    mpc_backend: String,

    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    #[arg(long, default_value_t = 31415)]
    port: u16,
}

fn parse_nonzero_execution_id(value: &str) -> Result<ExecutionId, String> {
    let execution_id = value.parse::<ExecutionId>()?;
    if execution_id.is_zero() {
        return Err("execution ID must be nonzero".to_owned());
    }
    Ok(execution_id)
}

#[derive(Clone)]
struct CoordinatorConnection {
    base: CoordinatorRPCServerConnectionBase,
}

impl RPCServerConnection for CoordinatorConnection {
    type Internal = CoordinatorRPCServerSharedBase;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self {
            base: CoordinatorRPCServerConnectionBase::new(internal, id),
        }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut rpc = StoffelCoordinatorRPCServer::into_rpc(self.clone());
        rpc.merge(CoordinatorRPCBaseServer::into_rpc(self.base))
            .expect("merge coordinator RPC modules");
        rpc
    }
}

#[async_trait]
impl StoffelCoordinatorRPCServer for CoordinatorConnection {
    async fn start_preprocessing(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::Preprocessing)
            .await
    }

    async fn reserve_input_masks(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputMaskReservation)
            .await
    }

    async fn collect_inputs(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputCollection)
            .await
    }

    async fn start_mpc(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::MPCExecution)
            .await
    }

    async fn send_output(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::OutputDistribution)
            .await
    }

    async fn finalize(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::ProgramFinished)
            .await
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    let args = Args::parse();
    let public_keys = parse_public_keys(&args.initial_mpc_nodes);
    let mut state = CoordinatorRPCServerSharedBase::new(args.n, args.t, public_keys)
        .expect("invalid coordinator roster");
    if let Some(execution_id) = args.execution_id {
        let program_hash = hex::decode(
            args.hash
                .as_deref()
                .expect("--hash is required with --execution-id"),
        )
        .expect("invalid hash")
        .try_into()
        .expect("hash must be 32 bytes");
        let min_output_shares = match args.mpc_backend.as_str() {
            "honeybadger" | "hb" => 2 * args.t + 1,
            "avss" => args.t + 1,
            other => panic!("unsupported --mpc-backend {other:?}"),
        };
        state
            .register_execution(ExecutionRegistration {
                execution_id,
                program_hash,
                n_inputs: args.n_inputs,
                output_clients: parse_public_keys(&args.output_clients),
                input_assignment: InputAssignment::default(),
                min_output_shares,
            })
            .expect("invalid initial execution");
    }

    let coord = OffChainCoordinatorServer::<CoordinatorConnection>::start_coord(
        state,
        &args.bind_addr,
        args.port,
        args.t,
        fs::read(&args.server_cert).expect("could not read server cert"),
        fs::read(&args.server_key).expect("could not read server key"),
    )
    .await
    .expect("failed to start coordinator");

    println!("Listening on {}:{}", args.bind_addr, args.port);
    wait_for_shutdown_signal().await;
    coord.shutdown().await;
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.expect("install SIGINT handler"),
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install interrupt handler");
}

fn parse_public_keys(cert_files: &[String]) -> Vec<Vec<u8>> {
    cert_files
        .iter()
        .map(|cert_file| {
            let cert_der = fs::read(cert_file)
                .unwrap_or_else(|_| panic!("could not read certificate file {cert_file}"));
            let (_, parsed_cert) = X509Certificate::from_der(&cert_der)
                .unwrap_or_else(|_| panic!("failed to parse X.509 certificate {cert_file}"));
            parsed_cert.public_key().subject_public_key.data.to_vec()
        })
        .collect()
}
