use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::net::mpc_engine::{AsyncMpcEngine, MpcEngine};
use crate::net::share_algebra;
use rustc_hash::FxHashMap;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, DeferredShare, DeferredShareOperation, ShareData,
    ShareDataFormat, ShareType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MultiplicationGroup {
    share_type: ShareType,
    format: ShareDataFormat,
}

#[derive(Debug)]
struct MultiplicationNode {
    share: Arc<DeferredShare>,
    predecessors: Vec<usize>,
    successors: Vec<usize>,
    dependency_depth: usize,
    remaining_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadyMultiplication {
    index: usize,
    remaining_depth: usize,
    secondary_priority: usize,
    share_id: u64,
}

impl Ord for ReadyMultiplication {
    fn cmp(&self, other: &Self) -> Ordering {
        self.remaining_depth
            .cmp(&other.remaining_depth)
            .then_with(|| self.secondary_priority.cmp(&other.secondary_priority))
            // Oldest source node wins deterministic ties.
            .then_with(|| other.share_id.cmp(&self.share_id))
    }
}

#[derive(Debug, Clone, Copy)]
enum SchedulePriority {
    SourceOrder,
    SuccessorFanout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadyBackwardMultiplication {
    index: usize,
    primary_priority: i128,
    secondary_priority: i128,
    tertiary_priority: usize,
    share_id: u64,
}

impl Ord for ReadyBackwardMultiplication {
    fn cmp(&self, other: &Self) -> Ordering {
        self.primary_priority
            .cmp(&other.primary_priority)
            .then_with(|| self.secondary_priority.cmp(&other.secondary_priority))
            .then_with(|| self.tertiary_priority.cmp(&other.tertiary_priority))
            .then_with(|| other.share_id.cmp(&self.share_id))
    }
}

impl PartialOrd for ReadyBackwardMultiplication {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy)]
enum BackwardSchedulePriority {
    CriticalDepth,
    CapacityBalance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadyDeadlineMultiplication {
    index: usize,
    deadline: usize,
    share_id: u64,
}

impl Ord for ReadyDeadlineMultiplication {
    fn cmp(&self, other: &Self) -> Ordering {
        // Earlier backward-assigned rounds are more urgent.
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.share_id.cmp(&self.share_id))
    }
}

impl PartialOrd for ReadyDeadlineMultiplication {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for ReadyMultiplication {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Resolve all deferred products reachable from `roots` and return ordinary
/// materialized shares in the same order.
///
/// The scheduler reduces the full share-expression graph to a multiplication
/// DAG: local linear nodes forward the frontier of their nearest interactive
/// ancestors, while multiply nodes introduce a new dependency vertex. Ready
/// vertices of the same runtime type and representation are issued together,
/// bounded by the backend's declared native session capacity.
pub(crate) async fn resolve_deferred_shares<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    roots: &[ShareData],
) -> VmResult<Vec<ShareData>> {
    let multiplications = build_multiplication_dag(roots);
    if multiplications.is_empty() {
        return materialize_roots(engine, roots).await;
    }

    execute_multiplication_dag(engine, &multiplications).await?;

    materialize_roots(engine, roots).await
}

/// Construct a deferred multiplication without turning a public constant into
/// an interactive lane. Public/public products remain public; multiplying a
/// secret by an integral public share becomes a local scalar operation. Values
/// that cannot be represented by the backend's scalar API (notably fixed-point
/// constants) are materialized and retain the ordinary interactive semantics.
pub(crate) async fn defer_multiply_share<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    share_type: ShareType,
    left: ShareData,
    right: ShareData,
) -> VmResult<ShareData> {
    let left_public = left.public_input();
    let right_public = right.public_input();

    if let (Some(left_input), Some(right_input)) = (left_public, right_public) {
        if let Some(product) = public_product(share_type, left_input, right_input) {
            return Ok(product);
        }
    }

    if right_public.is_none() {
        if let Some(scalar) = left_public.and_then(public_scalar) {
            let format = right.format();
            return Ok(ShareData::deferred(
                share_type,
                format,
                DeferredShareOperation::MulScalar {
                    share: right,
                    scalar,
                },
            ));
        }
    }
    if left_public.is_none() {
        if let Some(scalar) = right_public.and_then(public_scalar) {
            let format = left.format();
            return Ok(ShareData::deferred(
                share_type,
                format,
                DeferredShareOperation::MulScalar {
                    share: left,
                    scalar,
                },
            ));
        }
    }

    let left = materialize_public_share_async(engine, &left).await?;
    let right = materialize_public_share_async(engine, &right).await?;
    if left.format() != right.format() {
        return Err(VmError::ShareDataFormatMismatch {
            operation: "async_multiply_share",
            left: left.format().as_str(),
            right: right.format().as_str(),
        });
    }
    Ok(ShareData::deferred_multiply(share_type, left, right))
}

pub(crate) fn multiplication_requires_protocol(
    share_type: ShareType,
    left: &ShareData,
    right: &ShareData,
) -> bool {
    let left_public = left.public_input();
    let right_public = right.public_input();
    if let (Some(left), Some(right)) = (left_public, right_public) {
        if public_product(share_type, left, right).is_some() {
            return false;
        }
    }
    if right_public.is_none() && left_public.and_then(public_scalar).is_some() {
        return false;
    }
    if left_public.is_none() && right_public.and_then(public_scalar).is_some() {
        return false;
    }
    true
}

fn public_scalar(input: ClearShareInput) -> Option<i64> {
    match input.value() {
        ClearShareValue::Integer(value) => Some(value),
        ClearShareValue::UnsignedInteger(value) => i64::try_from(value).ok(),
        ClearShareValue::Boolean(value) => Some(i64::from(value)),
        ClearShareValue::FixedPoint(_) => None,
    }
}

fn public_product(
    share_type: ShareType,
    left: ClearShareInput,
    right: ClearShareInput,
) -> Option<ShareData> {
    if left.share_type() != share_type || right.share_type() != share_type {
        return None;
    }
    let value = match (left.value(), right.value()) {
        (ClearShareValue::Integer(left), ClearShareValue::Integer(right))
            if share_type != ShareType::boolean() =>
        {
            let ShareType::SecretInt { bit_length } = share_type else {
                return None;
            };
            ClearShareValue::Integer(wrap_signed(
                i128::from(left) * i128::from(right),
                bit_length,
            )?)
        }
        (ClearShareValue::UnsignedInteger(left), ClearShareValue::UnsignedInteger(right)) => {
            let ShareType::SecretUInt { bit_length } = share_type else {
                return None;
            };
            ClearShareValue::UnsignedInteger(wrap_unsigned(
                u128::from(left) * u128::from(right),
                bit_length,
            )?)
        }
        (ClearShareValue::Boolean(left), ClearShareValue::Boolean(right))
            if share_type == ShareType::boolean() =>
        {
            ClearShareValue::Boolean(left && right)
        }
        // Fixed-point multiplication is defined over each backend's encoded
        // representation and truncation protocol. Recomputing it as an f64
        // expression could change rounding, so retain the protocol operation.
        _ => return None,
    };
    Some(ShareData::public(ClearShareInput::new(share_type, value)))
}

fn wrap_signed(value: i128, bit_length: usize) -> Option<i64> {
    if bit_length == 0 || bit_length > 64 {
        return None;
    }
    if bit_length == 64 {
        return Some(value as i64);
    }
    let modulus = 1i128 << bit_length;
    let sign_bit = 1i128 << (bit_length - 1);
    let truncated = value.rem_euclid(modulus);
    Some(if truncated >= sign_bit {
        (truncated - modulus) as i64
    } else {
        truncated as i64
    })
}

fn wrap_unsigned(value: u128, bit_length: usize) -> Option<u64> {
    if bit_length == 0 || bit_length > 64 {
        return None;
    }
    if bit_length == 64 {
        Some(value as u64)
    } else {
        Some((value % (1u128 << bit_length)) as u64)
    }
}

pub(crate) async fn materialize_public_share_async<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    share: &ShareData,
) -> VmResult<ShareData> {
    let ShareData::Public(public) = share else {
        return Ok(share.materialized().unwrap_or(share).clone());
    };
    if let Some(materialized) = public.materialized() {
        return Ok(materialized.clone());
    }
    let materialized = engine
        .input_share_async(public.input())
        .await
        .map_mpc_backend_err("async_input_share")?;
    let _ = public.set_materialized(materialized.clone());
    Ok(public.materialized().unwrap_or(&materialized).clone())
}

async fn materialize_roots<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    roots: &[ShareData],
) -> VmResult<Vec<ShareData>> {
    let mut materialized = Vec::with_capacity(roots.len());
    for root in roots {
        if matches!(root, ShareData::Public(_)) {
            materialized.push(materialize_public_share_async(engine, root).await?);
        } else {
            materialized.push(materialize_local_share(engine, root)?);
        }
    }
    Ok(materialized)
}

fn collect_unresolved_nodes(roots: &[ShareData]) -> Vec<Arc<DeferredShare>> {
    let mut by_id: FxHashMap<u64, Arc<DeferredShare>> = FxHashMap::default();
    let mut pending = roots.to_vec();

    while let Some(share) = pending.pop() {
        let Some(node) = share.deferred_node() else {
            continue;
        };
        if node.resolved().is_some() || by_id.contains_key(&node.id()) {
            continue;
        }
        by_id.insert(node.id(), node.clone());
        node.operation()
            .visit_operands(|operand| pending.push(operand.clone()));
    }

    let mut nodes: Vec<_> = by_id.into_values().collect();
    nodes.sort_unstable_by_key(|node| node.id());
    nodes
}

fn build_multiplication_dag(roots: &[ShareData]) -> Vec<MultiplicationNode> {
    let deferred = collect_unresolved_nodes(roots);
    let mut frontiers: FxHashMap<u64, Vec<usize>> = FxHashMap::default();
    let mut multiplications = Vec::<MultiplicationNode>::new();

    for node in &deferred {
        let mut predecessors = Vec::new();
        node.operation().visit_operands(|operand| {
            let Some(parent) = operand.deferred_node() else {
                return;
            };
            if parent.resolved().is_some() {
                return;
            }
            if let Some(frontier) = frontiers.get(&parent.id()) {
                predecessors.extend(frontier.iter().copied());
            }
        });
        predecessors.sort_unstable();
        predecessors.dedup();

        if node.operation().is_multiply() {
            let index = multiplications.len();
            let dependency_depth = 1 + predecessors
                .iter()
                .map(|predecessor| multiplications[*predecessor].dependency_depth)
                .max()
                .unwrap_or(0);
            multiplications.push(MultiplicationNode {
                share: node.clone(),
                predecessors,
                successors: Vec::new(),
                dependency_depth,
                remaining_depth: 1,
            });
            frontiers.insert(node.id(), vec![index]);
        } else {
            frontiers.insert(node.id(), predecessors);
        }
    }

    for index in 0..multiplications.len() {
        for predecessor in multiplications[index].predecessors.clone() {
            multiplications[predecessor].successors.push(index);
        }
    }

    // Node identities are allocated after all of their operands, so reverse
    // identity order is a valid reverse topological order.
    for index in (0..multiplications.len()).rev() {
        multiplications[index].remaining_depth = 1 + multiplications[index]
            .successors
            .iter()
            .map(|successor| multiplications[*successor].remaining_depth)
            .max()
            .unwrap_or(0);
    }

    multiplications
}

async fn execute_multiplication_dag<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    multiplications: &[MultiplicationNode],
) -> VmResult<()> {
    if multiplications.is_empty() {
        return Ok(());
    }

    let capacity = engine
        .multiplication_batch_capacity()
        .unwrap_or(usize::MAX)
        .max(1);
    maybe_write_scheduler_dag(multiplications, capacity)?;
    let plan = select_multiplication_plan(multiplications, capacity)?;

    for (group, round) in plan {
        let mut pairs = Vec::with_capacity(round.len());
        for index in &round {
            let operation = multiplications[*index].share.operation();
            let DeferredShareOperation::Multiply { left, right } = operation else {
                return Err(VmError::Message(
                    "deferred MPC scheduler indexed a non-multiplication node".to_owned(),
                ));
            };
            let left = materialize_local_share(engine, left)?;
            let right = materialize_local_share(engine, right)?;
            pairs.push((left.as_bytes().to_vec(), right.as_bytes().to_vec()));
        }

        let products = engine
            .batch_multiply_share_async(group.share_type, &pairs)
            .await
            .map_mpc_backend_err("async_batch_multiply_share")?;
        if products.len() != round.len() {
            return Err(VmError::Message(format!(
                "MPC backend returned {} products for a deferred batch of {}",
                products.len(),
                round.len()
            )));
        }

        for (index, product) in round.iter().copied().zip(products) {
            if product.format() != group.format {
                return Err(VmError::ShareDataFormatMismatch {
                    operation: "deferred_batch_multiply",
                    left: group.format.as_str(),
                    right: product.format().as_str(),
                });
            }
            let node = &multiplications[index].share;
            let _ = node.set_resolved(product);
        }
    }

    Ok(())
}

/// Persist the exact source-ordered multiplication graph for offline scheduler
/// analysis when explicitly requested. Pair logs produced by an MPC backend are
/// execution ordered, so they cannot reproduce deterministic source-order ties
/// after testing a different schedule. This opt-in graph keeps that distinction
/// explicit and has no cost when the environment variable is absent.
fn maybe_write_scheduler_dag(
    multiplications: &[MultiplicationNode],
    capacity: usize,
) -> VmResult<()> {
    use std::io::Write;

    let Some(path) = std::env::var_os("STOFFEL_MPC_SCHEDULER_DAG_OUT") else {
        return Ok(());
    };
    let count = u32::try_from(multiplications.len()).map_err(|_| {
        VmError::Message("scheduler DAG has more nodes than the diagnostic format supports".into())
    })?;
    let write = || -> std::io::Result<()> {
        let mut writer = std::io::BufWriter::new(std::fs::File::create(path)?);
        writer.write_all(b"STFSCH01")?;
        writer.write_all(&(capacity as u64).to_le_bytes())?;
        writer.write_all(&count.to_le_bytes())?;
        for (index, node) in multiplications.iter().enumerate() {
            writer.write_all(&(index as u32).to_le_bytes())?;
            writer.write_all(&node.share.id().to_le_bytes())?;
            writer.write_all(&(node.dependency_depth as u32).to_le_bytes())?;
            writer.write_all(&(node.remaining_depth as u32).to_le_bytes())?;
            writer.write_all(&(node.predecessors.len() as u32).to_le_bytes())?;
            for &predecessor in &node.predecessors {
                writer.write_all(&(predecessor as u32).to_le_bytes())?;
            }
        }
        writer.flush()
    };
    write().map_err(|error| {
        VmError::Message(format!("failed to write scheduler DAG diagnostic: {error}"))
    })
}

fn select_multiplication_plan(
    multiplications: &[MultiplicationNode],
    capacity: usize,
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    // Pre-plan multiple deterministic legal schedules and return the shortest.
    // The source-order plan is the historical HLFET scheduler, so retaining it
    // as a candidate makes every added priority monotonic: it can improve the
    // online round count but cannot regress it.
    let source_plan =
        plan_multiplication_dag(multiplications, capacity, SchedulePriority::SourceOrder)?;
    let source_rounds = source_plan.len();
    let lower_bound = multiplication_plan_lower_bound(multiplications, capacity, source_rounds);
    if source_rounds == lower_bound {
        emit_scheduler_diagnostics(source_rounds, None, None, None, source_rounds, lower_bound);
        return Ok(source_plan);
    }

    let fanout_plan =
        plan_multiplication_dag(multiplications, capacity, SchedulePriority::SuccessorFanout)?;
    let fanout_rounds = fanout_plan.len();
    debug_assert!(fanout_rounds >= lower_bound);
    if fanout_rounds == lower_bound {
        emit_scheduler_diagnostics(
            source_rounds,
            Some(fanout_rounds),
            None,
            None,
            fanout_rounds,
            lower_bound,
        );
        return Ok(fanout_plan);
    }

    let deadline_plan = plan_backward_deadline_dag(multiplications, capacity)?;
    let deadline_rounds = deadline_plan.len();
    if deadline_rounds == lower_bound {
        emit_scheduler_diagnostics(
            source_rounds,
            Some(fanout_rounds),
            Some(deadline_rounds),
            None,
            deadline_rounds,
            lower_bound,
        );
        return Ok(deadline_plan);
    }
    let pressure_plan = plan_backward_capacity_balance_dag(multiplications, capacity)?;
    let pressure_rounds = pressure_plan.len();
    let mut best = source_plan;
    for candidate in [fanout_plan, deadline_plan, pressure_plan] {
        if candidate.len() < best.len() {
            best = candidate;
        }
    }
    debug_assert!(best.len() >= lower_bound);
    emit_scheduler_diagnostics(
        source_rounds,
        Some(fanout_rounds),
        Some(deadline_rounds),
        Some(pressure_rounds),
        best.len(),
        lower_bound,
    );
    Ok(best)
}

fn emit_scheduler_diagnostics(
    source_rounds: usize,
    fanout_rounds: Option<usize>,
    deadline_rounds: Option<usize>,
    pressure_rounds: Option<usize>,
    selected_rounds: usize,
    lower_bound: usize,
) {
    if std::env::var_os("STOFFEL_MPC_SCHEDULER_DIAGNOSTICS").is_none() {
        return;
    }
    let label = |rounds: Option<usize>| {
        rounds
            .map(|rounds| rounds.to_string())
            .unwrap_or_else(|| "skipped".to_owned())
    };
    eprintln!(
        "MPC_SCHEDULER candidates source={} fanout={} backward_deadline={} \
backward_capacity_balance={} \
selected={} certified_lower_bound={} optimal={}",
        source_rounds,
        label(fanout_rounds),
        label(deadline_rounds),
        label(pressure_rounds),
        selected_rounds,
        lower_bound,
        selected_rounds == lower_bound,
    );
}

/// A cheap scheduler-independent lower bound on the number of multiplication
/// sessions required by the backend contract.
///
/// Every dependency chain consumes one session per multiplication. In
/// addition, different runtime share types/representations cannot share a
/// backend batch, so each compatibility group independently needs
/// `ceil(work / capacity)` sessions. Taking the larger bound is sound for every
/// scheduling priority and lets diagnostics distinguish proven optima from
/// merely good upper bounds.
fn multiplication_plan_lower_bound(
    multiplications: &[MultiplicationNode],
    capacity: usize,
    legal_upper_bound: usize,
) -> usize {
    assert!(capacity > 0);
    let critical_path = multiplications
        .iter()
        .map(|node| node.dependency_depth)
        .max()
        .unwrap_or(0);
    let mut work_by_group: FxHashMap<MultiplicationGroup, usize> = FxHashMap::default();
    for node in multiplications {
        *work_by_group.entry(multiplication_group(node)).or_default() += 1;
    }
    let grouped_work = work_by_group
        .into_values()
        .map(|work| work.div_ceil(capacity))
        .sum::<usize>();
    let basic_bound = critical_path.max(grouped_work);
    let mut lower_bound = basic_bound;
    for horizon in basic_bound..legal_upper_bound {
        if multiplication_window_horizon_infeasible(multiplications, capacity, horizon) {
            lower_bound = horizon + 1;
        }
    }
    lower_bound
}

/// Necessary capacity condition for a candidate horizon. A multiplication's
/// dependency depth is its earliest legal session; its remaining depth gives
/// the latest session from which all descendants can still finish. Every node
/// whose entire legal window lies inside `[first, last]` must execute there, so
/// more than `capacity * interval_length` such nodes is a machine-checkable
/// contradiction independent of the scheduling heuristic.
fn multiplication_window_horizon_infeasible(
    multiplications: &[MultiplicationNode],
    capacity: usize,
    horizon: usize,
) -> bool {
    if multiplications.is_empty() {
        return false;
    }
    let stride = horizon + 2;
    let mut forced = vec![0usize; stride * stride];
    let cell = |earliest: usize, latest: usize| earliest * stride + latest;
    for node in multiplications {
        let earliest = node.dependency_depth;
        let Some(latest) = horizon
            .checked_sub(node.remaining_depth)
            .map(|round| round + 1)
        else {
            return true;
        };
        if earliest > latest {
            return true;
        }
        forced[cell(earliest, latest)] += 1;
    }
    for earliest in (1..=horizon).rev() {
        for latest in 1..=horizon {
            forced[cell(earliest, latest)] = forced[cell(earliest, latest)]
                + forced[cell(earliest + 1, latest)]
                + forced[cell(earliest, latest - 1)]
                - forced[cell(earliest + 1, latest - 1)];
        }
    }
    for first in 1..=horizon {
        for last in first..=horizon {
            if forced[cell(first, last)] > capacity * (last - first + 1) {
                return true;
            }
        }
    }
    false
}

/// Build a reverse HLFET schedule, favoring nodes that jointly release the
/// greatest number of critical-depth parents, then use its round assignments
/// as forward deadlines. The two passes expose capacity pressure on both ends
/// of the DAG while each returned session remains a normal legal list-schedule
/// step.
fn plan_backward_deadline_dag(
    multiplications: &[MultiplicationNode],
    capacity: usize,
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    plan_backward_deadline_dag_with_priority(
        multiplications,
        capacity,
        BackwardSchedulePriority::CriticalDepth,
    )
}

/// Build an independent reverse schedule that balances the number of complete
/// capacity batches on either side of a ready multiplication. Its assignments
/// expose legal forward schedules that a longest-path reverse pass cannot,
/// while the outer portfolio retains every historical candidate as a
/// round-count fallback.
fn plan_backward_capacity_balance_dag(
    multiplications: &[MultiplicationNode],
    capacity: usize,
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    plan_backward_deadline_dag_with_priority(
        multiplications,
        capacity,
        BackwardSchedulePriority::CapacityBalance,
    )
}

fn plan_backward_deadline_dag_with_priority(
    multiplications: &[MultiplicationNode],
    capacity: usize,
    priority: BackwardSchedulePriority,
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    let backward = build_backward_schedule(multiplications, capacity, priority)?;
    let deadlines = backward_deadlines(multiplications.len(), &backward);
    plan_multiplication_dag_by_deadline(multiplications, capacity, &deadlines)
}

fn build_backward_schedule(
    multiplications: &[MultiplicationNode],
    capacity: usize,
    priority: BackwardSchedulePriority,
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    let mut remaining_successors: Vec<_> = multiplications
        .iter()
        .map(|node| node.successors.len())
        .collect();
    let mut ready: FxHashMap<MultiplicationGroup, BinaryHeap<ReadyBackwardMultiplication>> =
        FxHashMap::default();
    for (index, node) in multiplications.iter().enumerate() {
        if remaining_successors[index] == 0 {
            push_backward_ready(&mut ready, index, node, multiplications, capacity, priority);
        }
    }

    let mut scheduled = 0usize;
    let mut backward = Vec::new();
    while scheduled < multiplications.len() {
        let group = ready
            .iter()
            .filter_map(|(group, queue)| queue.peek().map(|item| (*group, *item)))
            .max_by(|(_, left), (_, right)| left.cmp(right))
            .map(|(group, _)| group)
            .ok_or_else(|| {
                VmError::Message(
                    "deferred MPC multiplication graph contains a dependency cycle".to_owned(),
                )
            })?;
        let queue = ready.get_mut(&group).expect("selected ready group exists");
        let mut round = Vec::with_capacity(capacity.min(queue.len()));
        while round.len() < capacity {
            let Some(item) = queue.pop() else {
                break;
            };
            round.push(item.index);
        }
        if queue.is_empty() {
            ready.remove(&group);
        }

        for &index in &round {
            scheduled += 1;
            for &predecessor in &multiplications[index].predecessors {
                remaining_successors[predecessor] -= 1;
                if remaining_successors[predecessor] == 0 {
                    push_backward_ready(
                        &mut ready,
                        predecessor,
                        &multiplications[predecessor],
                        multiplications,
                        capacity,
                        priority,
                    );
                }
            }
        }
        backward.push((group, round));
    }
    backward.reverse();
    Ok(backward)
}

fn backward_deadlines(
    multiplication_count: usize,
    backward: &[(MultiplicationGroup, Vec<usize>)],
) -> Vec<usize> {
    let mut deadlines = vec![usize::MAX; multiplication_count];
    for (round, (_, nodes)) in backward.iter().enumerate() {
        for &node in nodes {
            deadlines[node] = round;
        }
    }
    deadlines
}

fn push_backward_ready(
    ready: &mut FxHashMap<MultiplicationGroup, BinaryHeap<ReadyBackwardMultiplication>>,
    index: usize,
    node: &MultiplicationNode,
    multiplications: &[MultiplicationNode],
    capacity: usize,
    priority: BackwardSchedulePriority,
) {
    let group = multiplication_group(node);
    let critical_predecessors = node
        .predecessors
        .iter()
        .filter(|&&predecessor| {
            multiplications[predecessor].dependency_depth + 1 == node.dependency_depth
        })
        .count();
    let critical_successors = node
        .successors
        .iter()
        .filter(|&&successor| {
            multiplications[successor].dependency_depth == node.dependency_depth + 1
        })
        .count();
    let (primary_priority, secondary_priority, tertiary_priority) = match priority {
        BackwardSchedulePriority::CriticalDepth => (
            node.dependency_depth as i128,
            critical_predecessors as i128,
            node.predecessors.len(),
        ),
        BackwardSchedulePriority::CapacityBalance => (
            critical_predecessors as i128,
            backward_capacity_pressure(node, critical_successors, capacity),
            node.successors.len(),
        ),
    };
    ready
        .entry(group)
        .or_default()
        .push(ReadyBackwardMultiplication {
            index,
            primary_priority,
            secondary_priority,
            tertiary_priority,
            share_id: node.share.id(),
        });
}

/// Capacity-normalized branching pressure for reverse list scheduling.
///
/// Critical fan-in remains the primary key because a join synchronizes scarce
/// predecessor chains. Within that class, logarithmic fan-out rewards broad
/// downstream influence without allowing one enormous frontier to dominate.
/// Whole-batch terms reserve enough upstream work without over-expanding the
/// downstream frontier. This score never decides correctness: it constructs an
/// additional legal candidate and the scheduler retains the shortest candidate
/// plan.
fn backward_capacity_pressure(
    node: &MultiplicationNode,
    critical_successors: usize,
    capacity: usize,
) -> i128 {
    let predecessor_count = node.predecessors.len();
    let successor_count = node.successors.len();
    let quarter_capacity = (capacity / 4).max(1);
    2 * log2_one_plus(successor_count) as i128 + critical_successors as i128
        - 2 * log2_one_plus(predecessor_count) as i128
        - 4 * (successor_count / capacity) as i128
        + 8 * (predecessor_count / quarter_capacity) as i128
}

fn log2_one_plus(value: usize) -> usize {
    value
        .checked_add(1)
        .map_or(usize::BITS as usize, |value| value.ilog2() as usize)
}

fn plan_multiplication_dag_by_deadline(
    multiplications: &[MultiplicationNode],
    capacity: usize,
    deadlines: &[usize],
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    assert_eq!(multiplications.len(), deadlines.len());
    let mut indegrees: Vec<_> = multiplications
        .iter()
        .map(|node| node.predecessors.len())
        .collect();
    let mut ready: FxHashMap<MultiplicationGroup, BinaryHeap<ReadyDeadlineMultiplication>> =
        FxHashMap::default();
    for (index, node) in multiplications.iter().enumerate() {
        if indegrees[index] == 0 {
            push_deadline_ready(&mut ready, index, node, deadlines[index]);
        }
    }

    let mut completed = 0usize;
    let mut plan = Vec::new();
    while completed < multiplications.len() {
        let group = ready
            .iter()
            .filter_map(|(group, queue)| queue.peek().map(|item| (*group, *item)))
            .max_by(|(_, left), (_, right)| left.cmp(right))
            .map(|(group, _)| group)
            .ok_or_else(|| {
                VmError::Message(
                    "deferred MPC multiplication graph contains a dependency cycle".to_owned(),
                )
            })?;
        let queue = ready.get_mut(&group).expect("selected ready group exists");
        let mut round = Vec::with_capacity(capacity.min(queue.len()));
        while round.len() < capacity {
            let Some(item) = queue.pop() else {
                break;
            };
            round.push(item.index);
        }
        if queue.is_empty() {
            ready.remove(&group);
        }

        for &index in &round {
            completed += 1;
            for &successor in &multiplications[index].successors {
                indegrees[successor] -= 1;
                if indegrees[successor] == 0 {
                    push_deadline_ready(
                        &mut ready,
                        successor,
                        &multiplications[successor],
                        deadlines[successor],
                    );
                }
            }
        }
        plan.push((group, round));
    }
    Ok(plan)
}

fn push_deadline_ready(
    ready: &mut FxHashMap<MultiplicationGroup, BinaryHeap<ReadyDeadlineMultiplication>>,
    index: usize,
    node: &MultiplicationNode,
    deadline: usize,
) {
    ready
        .entry(multiplication_group(node))
        .or_default()
        .push(ReadyDeadlineMultiplication {
            index,
            deadline,
            share_id: node.share.id(),
        });
}

fn plan_multiplication_dag(
    multiplications: &[MultiplicationNode],
    capacity: usize,
    priority: SchedulePriority,
) -> VmResult<Vec<(MultiplicationGroup, Vec<usize>)>> {
    let mut indegrees: Vec<_> = multiplications
        .iter()
        .map(|node| node.predecessors.len())
        .collect();
    let mut ready: FxHashMap<MultiplicationGroup, BinaryHeap<ReadyMultiplication>> =
        FxHashMap::default();
    for (index, node) in multiplications.iter().enumerate() {
        if indegrees[index] == 0 {
            push_ready(&mut ready, index, node, priority);
        }
    }

    let mut completed = 0usize;
    let mut plan = Vec::new();
    while completed < multiplications.len() {
        let group = ready
            .iter()
            .filter_map(|(group, queue)| queue.peek().map(|item| (*group, *item)))
            .max_by(|(_, left), (_, right)| left.cmp(right))
            .map(|(group, _)| group)
            .ok_or_else(|| {
                VmError::Message(
                    "deferred MPC multiplication graph contains a dependency cycle".to_owned(),
                )
            })?;
        let queue = ready.get_mut(&group).expect("selected ready group exists");
        let mut round = Vec::with_capacity(capacity.min(queue.len()));
        while round.len() < capacity {
            let Some(item) = queue.pop() else {
                break;
            };
            round.push(item.index);
        }
        if queue.is_empty() {
            ready.remove(&group);
        }

        // Successors released by this protocol session become eligible only
        // for the next planned session.
        for &index in &round {
            completed += 1;
            for &successor in &multiplications[index].successors {
                indegrees[successor] -= 1;
                if indegrees[successor] == 0 {
                    push_ready(&mut ready, successor, &multiplications[successor], priority);
                }
            }
        }
        plan.push((group, round));
    }
    Ok(plan)
}

fn push_ready(
    ready: &mut FxHashMap<MultiplicationGroup, BinaryHeap<ReadyMultiplication>>,
    index: usize,
    node: &MultiplicationNode,
    priority: SchedulePriority,
) {
    let group = multiplication_group(node);
    let (remaining_depth, secondary_priority) = match priority {
        SchedulePriority::SourceOrder => (node.remaining_depth, 0),
        SchedulePriority::SuccessorFanout => (node.remaining_depth, node.successors.len()),
    };
    ready.entry(group).or_default().push(ReadyMultiplication {
        index,
        remaining_depth,
        secondary_priority,
        share_id: node.share.id(),
    });
}

fn multiplication_group(node: &MultiplicationNode) -> MultiplicationGroup {
    MultiplicationGroup {
        share_type: node.share.share_type(),
        format: node.share.format(),
    }
}

fn materialize_local_share<E: MpcEngine + ?Sized>(
    engine: &E,
    root: &ShareData,
) -> VmResult<ShareData> {
    if matches!(root, ShareData::Public(_)) {
        return materialize_public_share_sync(engine, root);
    }
    if let Some(materialized) = root.materialized() {
        return Ok(materialized.clone());
    }

    let mut stack = vec![(root.clone(), false)];
    while let Some((share, operands_visited)) = stack.pop() {
        if matches!(share, ShareData::Public(_)) {
            materialize_public_share_sync(engine, &share)?;
            continue;
        }
        if share.materialized().is_some() {
            continue;
        }
        let node = share.deferred_node().cloned().ok_or_else(|| {
            VmError::Message("deferred share lost its expression node".to_owned())
        })?;
        if node.operation().is_multiply() {
            return Err(VmError::Message(format!(
                "deferred multiplication {} was materialized before its dependencies completed",
                node.id()
            )));
        }

        if !operands_visited {
            stack.push((share, true));
            let mut operands = Vec::new();
            node.operation()
                .visit_operands(|operand| operands.push(operand.clone()));
            for operand in operands.into_iter().rev() {
                if operand.materialized().is_none() {
                    stack.push((operand, false));
                }
            }
            continue;
        }

        let result = evaluate_local_operation(engine, &node)?;
        let _ = node.set_resolved(result);
    }

    root.materialized().cloned().ok_or_else(|| {
        VmError::Message("failed to materialize deferred local share expression".to_owned())
    })
}

fn materialize_public_share_sync<E: MpcEngine + ?Sized>(
    engine: &E,
    share: &ShareData,
) -> VmResult<ShareData> {
    let ShareData::Public(public) = share else {
        return Ok(share.materialized().unwrap_or(share).clone());
    };
    if let Some(materialized) = public.materialized() {
        return Ok(materialized.clone());
    }
    let materialized = engine
        .input_share(public.input())
        .map_mpc_backend_err("input_share")?;
    let _ = public.set_materialized(materialized.clone());
    Ok(public.materialized().unwrap_or(&materialized).clone())
}

fn evaluate_local_operation<E: MpcEngine + ?Sized>(
    engine: &E,
    node: &DeferredShare,
) -> VmResult<ShareData> {
    let ty = node.share_type();
    let (template, result) = match node.operation() {
        DeferredShareOperation::Multiply { .. } => {
            return Err(VmError::Message(
                "interactive multiplication reached the local evaluator".to_owned(),
            ));
        }
        DeferredShareOperation::Add { left, right } => (
            left,
            engine
                .add_share_local(ty, left.as_bytes(), right.as_bytes())
                .map_mpc_backend_err("add_share_local")?,
        ),
        DeferredShareOperation::Sub { left, right } => (
            left,
            engine
                .sub_share_local(ty, left.as_bytes(), right.as_bytes())
                .map_mpc_backend_err("sub_share_local")?,
        ),
        DeferredShareOperation::Neg { share } => (
            share,
            engine
                .neg_share_local(ty, share.as_bytes())
                .map_mpc_backend_err("neg_share_local")?,
        ),
        DeferredShareOperation::AddScalar { share, scalar } => (
            share,
            engine
                .add_share_scalar_local(ty, share.as_bytes(), *scalar)
                .map_mpc_backend_err("add_share_scalar_local")?,
        ),
        DeferredShareOperation::SubScalar { share, scalar } => (
            share,
            engine
                .sub_share_scalar_local(ty, share.as_bytes(), *scalar)
                .map_mpc_backend_err("sub_share_scalar_local")?,
        ),
        DeferredShareOperation::ScalarSub { scalar, share } => (
            share,
            engine
                .scalar_sub_share_local(ty, *scalar, share.as_bytes())
                .map_mpc_backend_err("scalar_sub_share_local")?,
        ),
        DeferredShareOperation::DivScalar { share, scalar } => (
            share,
            engine
                .div_share_scalar_local(ty, share.as_bytes(), *scalar)
                .map_mpc_backend_err("div_share_scalar_local")?,
        ),
        DeferredShareOperation::MulScalar { share, scalar } => (
            share,
            engine
                .mul_share_scalar_local(ty, share.as_bytes(), *scalar)
                .map_mpc_backend_err("mul_share_scalar_local")?,
        ),
        DeferredShareOperation::MulField { share, scalar } => (
            share,
            engine
                .mul_share_field_local(ty, share.as_bytes(), scalar)
                .map_mpc_backend_err("mul_share_field_local")?,
        ),
        DeferredShareOperation::AddField { share, field } => (
            share,
            engine
                .add_share_field_local(ty, share.as_bytes(), field)
                .map_mpc_backend_err("add_share_field_local")?,
        ),
    };

    share_algebra::preserve_share_data_format_for_curve(engine.curve_config(), template, result)
        .map_mpc_backend_err("preserve_share_data_format")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opaque(value: u8) -> ShareData {
        ShareData::Opaque(vec![value].into())
    }

    fn multiply(ty: ShareType, left: ShareData, right: ShareData) -> ShareData {
        ShareData::deferred_multiply(ty, left, right)
    }

    fn add(ty: ShareType, left: ShareData, right: ShareData) -> ShareData {
        ShareData::deferred(
            ty,
            ShareDataFormat::Opaque,
            DeferredShareOperation::Add { left, right },
        )
    }

    #[test]
    fn scheduler_selects_a_shorter_fanout_plan_without_regressing_source_order() {
        let ty = ShareType::secret_int(64);
        let first = multiply(ty, opaque(1), opaque(2));
        let second = multiply(ty, opaque(3), opaque(4));
        let shared_parent = multiply(ty, opaque(5), opaque(6));

        // The first sink needs all three source products. The other two sinks
        // both need `shared_parent`. With capacity two, source-order HLFET
        // takes four sessions, while the equally legal fanout tie-break starts
        // the shared parent immediately and completes in three.
        let all_sources = add(
            ty,
            add(ty, first.clone(), second.clone()),
            shared_parent.clone(),
        );
        let roots = vec![
            multiply(ty, all_sources, opaque(7)),
            multiply(ty, shared_parent.clone(), opaque(8)),
            multiply(ty, shared_parent, opaque(9)),
        ];
        let dag = build_multiplication_dag(&roots);

        let source = plan_multiplication_dag(&dag, 2, SchedulePriority::SourceOrder)
            .expect("source-order schedule should be legal");
        let fanout = plan_multiplication_dag(&dag, 2, SchedulePriority::SuccessorFanout)
            .expect("fanout schedule should be legal");
        let selected =
            select_multiplication_plan(&dag, 2).expect("scheduler should select a legal plan");

        assert_eq!(source.len(), 4);
        assert_eq!(fanout.len(), 3);
        assert_eq!(selected.len(), fanout.len());
        assert_eq!(
            multiplication_plan_lower_bound(&dag, 2, selected.len()),
            selected.len()
        );
        assert!(selected.len() <= source.len());
    }

    #[test]
    fn scheduler_uses_backward_capacity_pressure_to_start_prerequisites_early() {
        let ty = ShareType::secret_int(64);
        let first = multiply(ty, opaque(1), opaque(2));
        let second = multiply(ty, opaque(3), opaque(4));
        let third = multiply(ty, opaque(5), opaque(6));
        let all_sources = add(ty, add(ty, first.clone(), second.clone()), third.clone());
        let first_sink = multiply(ty, all_sources.clone(), opaque(7));
        let second_sink = multiply(ty, all_sources, opaque(8));
        let third_sink = multiply(ty, add(ty, second, third), opaque(9));
        let final_inputs = add(
            ty,
            add(ty, first, first_sink),
            add(ty, second_sink, third_sink),
        );
        let roots = vec![multiply(ty, final_inputs, opaque(10))];
        let dag = build_multiplication_dag(&roots);

        let source = plan_multiplication_dag(&dag, 2, SchedulePriority::SourceOrder)
            .expect("source-order schedule should be legal");
        let fanout = plan_multiplication_dag(&dag, 2, SchedulePriority::SuccessorFanout)
            .expect("fanout schedule should be legal");
        let deadline = plan_backward_deadline_dag(&dag, 2)
            .expect("backward-deadline schedule should be legal");
        let selected =
            select_multiplication_plan(&dag, 2).expect("scheduler should select a legal plan");

        assert_eq!(source.len(), 5);
        assert_eq!(fanout.len(), 5);
        assert_eq!(deadline.len(), 4);
        assert_eq!(selected.len(), deadline.len());
        assert_eq!(
            multiplication_plan_lower_bound(&dag, 2, selected.len()),
            selected.len()
        );
        assert!(selected.len() <= source.len());
    }

    #[test]
    fn scheduler_certificate_accounts_for_incompatible_batch_groups() {
        let wide = ShareType::secret_int(64);
        let bit = ShareType::secret_int(1);
        let roots = vec![
            multiply(wide, opaque(1), opaque(2)),
            multiply(bit, opaque(3), opaque(4)),
        ];
        let dag = build_multiplication_dag(&roots);
        let selected =
            select_multiplication_plan(&dag, 2).expect("scheduler should select a legal plan");

        // Both multiplications are independent and the raw width is two, but
        // the backend cannot put different ShareTypes in one homogeneous
        // batch. Each compatibility group therefore requires its own session.
        assert_eq!(multiplication_plan_lower_bound(&dag, 2, selected.len()), 2);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn scheduler_certificate_detects_interval_capacity_pressure() {
        let ty = ShareType::secret_int(64);
        let root = multiply(ty, opaque(1), opaque(2));
        let roots = (0..4)
            .map(|value| multiply(ty, root.clone(), opaque(value + 3)))
            .collect::<Vec<_>>();
        let dag = build_multiplication_dag(&roots);
        let selected =
            select_multiplication_plan(&dag, 3).expect("scheduler should select a legal plan");

        // Critical path and raw work both say two rounds. The root consumes the
        // first round by itself, forcing all four children into a single
        // three-wide second-round window, so two rounds are impossible.
        assert_eq!(selected.len(), 3);
        assert_eq!(multiplication_plan_lower_bound(&dag, 3, selected.len()), 3);
        assert!(multiplication_window_horizon_infeasible(&dag, 3, 2));
        assert!(!multiplication_window_horizon_infeasible(&dag, 3, 3));
    }
}
