//! Long-running, VM-only workloads for eBPF sampling and repeatable throughput checks.
//!
//! The async workload deliberately uses only clear local instructions. The dummy
//! engine exists to exercise the VM's cooperative concurrent executor without
//! measuring any MPC protocol implementation.

use std::collections::HashMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use stoffel_vm::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::net::mpc_engine::{
    AsyncMpcEngine, MpcCapabilities, MpcEngine, MpcEngineResult, MpcSessionTopology,
};

const DEFAULT_SECONDS: u64 = 30;
const SERIAL_LOOP_ITERATIONS: usize = 1_000_000;
const CONCURRENT_LOOP_ITERATIONS: usize = 100_000;
const CONCURRENT_INVOCATIONS: usize = 16;

struct NoProtocolEngine;

impl MpcEngine for NoProtocolEngine {
    fn protocol_name(&self) -> &'static str {
        "vm-profile-no-protocol"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(1, 0, 1, 0).expect("valid single-party profile topology")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        unreachable!("the VM-only profile never creates shares")
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        unreachable!("the VM-only profile never opens shares")
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::empty()
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for NoProtocolEngine {
    async fn input_share_async(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        unreachable!("the VM-only profile never creates shares")
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        unreachable!("the VM-only profile never opens shares")
    }
}

fn local_loop(name: &str, iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 4);

    VMFunction::new(
        name.to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::LDI(3, Value::I64(0)),
            Instruction::ADD(3, 3, 1),
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(3),
        ],
        labels,
    )
}

fn vm_with_loop(iterations: usize) -> VirtualMachine {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();
    vm.register_function(local_loop("profile_loop", iterations));
    vm
}

fn run_serial(duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let mut vm = vm_with_loop(SERIAL_LOOP_ITERATIONS);
    let expected = Value::I64(SERIAL_LOOP_ITERATIONS as i64);
    let started = Instant::now();
    let mut runs = 0u64;

    while runs == 0 || started.elapsed() < duration {
        let result = vm.execute_for_benchmark("profile_loop")?;
        if result != expected {
            return Err(format!("unexpected serial result: {result:?}").into());
        }
        black_box(result);
        runs += 1;
    }

    report(
        "serial-local",
        started.elapsed(),
        runs,
        SERIAL_LOOP_ITERATIONS,
    );
    Ok(())
}

fn run_concurrent(duration: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let vm = vm_with_loop(CONCURRENT_LOOP_ITERATIONS);
    let engine = NoProtocolEngine;
    let entries = vec!["profile_loop"; CONCURRENT_INVOCATIONS];
    let expected = Value::I64(CONCURRENT_LOOP_ITERATIONS as i64);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let started = Instant::now();
    let mut batches = 0u64;

    while batches == 0 || started.elapsed() < duration {
        let results = runtime.block_on(vm.execute_many_async(entries.iter().copied(), &engine))?;
        if results.len() != CONCURRENT_INVOCATIONS
            || results.iter().any(|result| result != &expected)
        {
            return Err(format!("unexpected concurrent results: {results:?}").into());
        }
        black_box(results);
        batches += 1;
    }

    report(
        "concurrent-local-16",
        started.elapsed(),
        batches * CONCURRENT_INVOCATIONS as u64,
        CONCURRENT_LOOP_ITERATIONS,
    );
    Ok(())
}

fn report(name: &str, elapsed: Duration, executions: u64, loop_iterations: usize) {
    let loop_iterations = executions as f64 * loop_iterations as f64;
    let vm_instructions = loop_iterations * 4.0 + executions as f64 * 5.0;
    println!(
        "workload={name} elapsed_seconds={:.6} executions={executions} loop_iterations_per_second={:.3} vm_instructions_per_second={:.3}",
        elapsed.as_secs_f64(),
        loop_iterations / elapsed.as_secs_f64(),
        vm_instructions / elapsed.as_secs_f64(),
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let workload = args.next().unwrap_or_else(|| "serial".to_owned());
    let seconds = args
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_SECONDS);
    let duration = Duration::from_secs(seconds);

    match workload.as_str() {
        "serial" | "serial-local" => run_serial(duration),
        "concurrent" | "concurrent-local" => run_concurrent(duration),
        _ => Err(format!(
            "unknown workload {workload:?}; expected serial-local or concurrent-local"
        )
        .into()),
    }
}
