use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineMultiplication, MpcEngineResult, MpcSessionTopology,
    ShareAlgebraResult,
};
use stoffel_vm::runtime_hooks::HookEvent;
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, TableRef, Value,
};
use stoffel_vm_types::instructions::Instruction;

/// HoneyBadger's default per-session pair limit at the benchmark topology
/// threshold `t=1`: `128 * (t+1)`. Each chunk is awaited sequentially and is
/// therefore one online communication round.
const MODELED_MPC_BATCH_CAPACITY: usize = 256;

#[derive(Default)]
struct CountingEngine {
    scalar_mul_calls: AtomicUsize,
    batch_mul_calls: AtomicUsize,
    batch_mul_items: AtomicUsize,
    // === Lever-B / depth instrumentation (measurement only) ===
    // public_operand_muls: number of individual multiply PAIRS executed whose
    // value (the round-charging `ab` term) has at least one operand that traces
    // back to a compile-time public literal (`Share.from_clear_int` / a literal
    // vector) through only LOCAL ops (never through a prior multiply). These are
    // exactly the `bits_xor` (secret⊕public) and constant-fold multiplies that
    // lever B could turn into a local `mul_scalar`, so this is lever B's headroom.
    public_operand_muls: AtomicUsize,
    // both_public_muls: subset where BOTH operands are public literals (the
    // multiply is fully constant-foldable, not just lever-B-local).
    both_public_muls: AtomicUsize,
    // max_mul_depth: critical-path multiply depth = the theoretical round floor
    // with perfect batching. A share's depth is the number of multiplies on the
    // longest data-dependency path from inputs; a multiply output is
    // max(operand depths)+1, local ops keep the max, inputs are depth 0.
    max_mul_depth: AtomicUsize,
    // === Per-depth histogram instrumentation (measurement only) ===
    // call_seq: monotonically allocated id per multiply ROUND (one scalar call or
    // one batch call). pair_log: one row per multiply pair executed, tagging the
    // round it ran in, the output depth, and whether it had a public operand.
    call_seq: AtomicUsize,
    pair_seq: AtomicUsize,
    pair_log: std::sync::Mutex<Vec<PairRecord>>,
    /// One per scalar open or native batch-open invocation. HoneyBadger's batch
    /// open sends all shares in one broadcast and has no multiply-style width
    /// chunking, so every non-empty call is exactly one online round.
    open_rounds: AtomicUsize,
    scalar_open_rounds: AtomicUsize,
    batch_open_rounds: AtomicUsize,
}

/// One executed multiply pair, for the per-depth round histogram.
#[derive(Clone)]
struct PairRecord {
    /// Stable multiplication-DAG node id.
    pair_id: u32,
    /// Multiplication nodes whose outputs feed this pair through zero or more
    /// local operations. Redundant transitive parents are legal.
    parents: Vec<u32>,
    /// Round id (one per scalar multiply call or per batch_multiply call).
    call_id: u32,
    /// Output (critical-path) depth of this pair: max(operand depths)+1.
    depth: u32,
    /// At least one operand traces to a public literal through only local ops.
    pub_operand: bool,
    /// Both operands public (fully constant-foldable).
    both_public: bool,
}

/// Validate the executed multiplication DAG and return its critical-path depth.
/// The packed frontier metadata follows dependencies through arbitrary local
/// linear operations, so every parent edge must point to an earlier pair and
/// reproduce the recorded `max(parent depth) + 1` depth exactly.
fn validate_pair_dag(log: &[PairRecord]) -> usize {
    let mut depths = Vec::with_capacity(log.len());
    let mut calls = Vec::with_capacity(log.len());
    for (expected_id, record) in log.iter().enumerate() {
        assert_eq!(
            record.pair_id as usize, expected_id,
            "pair ids must be dense"
        );
        let mut parent_depth = 0u32;
        for &parent in &record.parents {
            let parent = parent as usize;
            assert!(parent < expected_id, "DAG edge must point backward");
            assert!(
                calls[parent] < record.call_id,
                "a multiplication must execute strictly after every parent round"
            );
            parent_depth = parent_depth.max(depths[parent]);
        }
        assert_eq!(
            record.depth,
            parent_depth + 1,
            "recorded depth must equal the multiplication-DAG depth"
        );
        depths.push(record.depth);
        calls.push(record.call_id);
    }
    depths.into_iter().max().unwrap_or(0) as usize
}

fn weak_component_sizes(log: &[PairRecord]) -> Vec<usize> {
    fn find(parents: &mut [usize], mut node: usize) -> usize {
        while parents[node] != node {
            parents[node] = parents[parents[node]];
            node = parents[node];
        }
        node
    }

    let mut components: Vec<_> = (0..log.len()).collect();
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            let left = find(&mut components, node);
            let right = find(&mut components, parent as usize);
            if left != right {
                components[right] = left;
            }
        }
    }
    let mut sizes = std::collections::BTreeMap::new();
    for node in 0..log.len() {
        let root = find(&mut components, node);
        *sizes.entry(root).or_insert(0usize) += 1;
    }
    let mut sizes: Vec<_> = sizes.into_values().collect();
    sizes.sort_unstable_by(|left, right| right.cmp(left));
    sizes
}

/// A legal capacity-aware list schedule of the executed multiplication DAG.
/// Ready nodes with the longest remaining path are prioritized, which preserves
/// scarce critical-path work while filling every protocol session when possible.
fn dag_list_schedule(log: &[PairRecord], capacity: usize) -> Vec<Vec<usize>> {
    assert!(capacity > 0);
    if log.is_empty() {
        return Vec::new();
    }
    let mut successors = vec![Vec::new(); log.len()];
    let mut indegree = vec![0usize; log.len()];
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            successors[parent as usize].push(node);
            indegree[node] += 1;
        }
    }
    let mut bottom_level = vec![1usize; log.len()];
    for node in (0..log.len()).rev() {
        bottom_level[node] = 1 + successors[node]
            .iter()
            .map(|&successor| bottom_level[successor])
            .max()
            .unwrap_or(0);
    }

    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut ready = BinaryHeap::new();
    for node in 0..log.len() {
        if indegree[node] == 0 {
            ready.push((bottom_level[node], Reverse(node)));
        }
    }
    let mut scheduled = 0usize;
    let mut rounds = Vec::new();
    while scheduled < log.len() {
        assert!(!ready.is_empty(), "multiplication graph must be acyclic");
        // Successors released by this session cannot execute until the next
        // communication round, even if capacity remains in the current one.
        let mut session = Vec::with_capacity(capacity.min(ready.len()));
        for _ in 0..capacity {
            let Some((_, Reverse(node))) = ready.pop() else {
                break;
            };
            session.push(node);
        }
        scheduled += session.len();
        for &node in &session {
            for &successor in &successors[node] {
                indegree[successor] -= 1;
                if indegree[successor] == 0 {
                    ready.push((bottom_level[successor], Reverse(successor)));
                }
            }
        }
        rounds.push(session);
    }
    rounds
}

/// Mirror-image list schedule built from the sinks backwards. A forward
/// critical-path heuristic can make locally reasonable choices that create a
/// sparse drain; scheduling the reversed DAG independently is a cheap generic
/// way to expose that asymmetry. Returned rounds are restored to forward order.
fn dag_backward_list_schedule(log: &[PairRecord], capacity: usize) -> Vec<Vec<usize>> {
    dag_backward_priority_list_schedule(log, capacity, BackwardPriority::SourceOrder)
}

#[derive(Debug, Clone, Copy)]
enum BackwardPriority {
    SourceOrder,
    CriticalPredecessorFanIn,
}

fn dag_backward_priority_list_schedule(
    log: &[PairRecord],
    capacity: usize,
    priority: BackwardPriority,
) -> Vec<Vec<usize>> {
    assert!(capacity > 0);
    if log.is_empty() {
        return Vec::new();
    }
    let mut remaining_successors = vec![0usize; log.len()];
    for record in log {
        for &parent in &record.parents {
            remaining_successors[parent as usize] += 1;
        }
    }
    let critical_predecessor_count: Vec<_> = log
        .iter()
        .map(|record| {
            record
                .parents
                .iter()
                .filter(|&&parent| log[parent as usize].depth + 1 == record.depth)
                .count()
        })
        .collect();
    let key = |node: usize| {
        let ascending = usize::MAX - node;
        match priority {
            BackwardPriority::SourceOrder => [log[node].depth as usize, 0, 0, 0, 0, ascending],
            BackwardPriority::CriticalPredecessorFanIn => [
                log[node].depth as usize,
                critical_predecessor_count[node],
                log[node].parents.len(),
                0,
                0,
                ascending,
            ],
        }
    };

    use std::collections::BinaryHeap;
    let mut ready = BinaryHeap::new();
    for node in 0..log.len() {
        if remaining_successors[node] == 0 {
            // `depth` is the reverse problem's bottom level.
            ready.push((key(node), node));
        }
    }
    let mut scheduled = 0usize;
    let mut reverse_rounds = Vec::new();
    while scheduled < log.len() {
        assert!(!ready.is_empty(), "multiplication graph must be acyclic");
        let mut round = Vec::with_capacity(capacity.min(ready.len()));
        for _ in 0..capacity {
            let Some((_, node)) = ready.pop() else {
                break;
            };
            round.push(node);
        }
        scheduled += round.len();
        for &node in &round {
            for &parent in &log[node].parents {
                let parent = parent as usize;
                remaining_successors[parent] -= 1;
                if remaining_successors[parent] == 0 {
                    ready.push((key(parent), parent));
                }
            }
        }
        reverse_rounds.push(round);
    }
    reverse_rounds.reverse();
    reverse_rounds
}

/// Forward list scheduling prioritized by the round assigned by an independent
/// legal backward schedule. The reverse pass gives prerequisites of congested
/// sink regions earlier deadlines than bottom level alone can express.
fn dag_backward_deadline_schedule(log: &[PairRecord], capacity: usize) -> Vec<Vec<usize>> {
    assert!(capacity > 0);
    if log.is_empty() {
        return Vec::new();
    }
    let backward = dag_backward_list_schedule(log, capacity);
    dag_forward_from_backward_schedule(log, capacity, &backward)
}

fn dag_forward_from_backward_schedule(
    log: &[PairRecord],
    capacity: usize,
    backward: &[Vec<usize>],
) -> Vec<Vec<usize>> {
    let mut deadline = vec![usize::MAX; log.len()];
    for (round, nodes) in backward.iter().enumerate() {
        for &node in nodes {
            deadline[node] = round;
        }
    }

    dag_forward_by_deadlines(log, capacity, &deadline)
}

fn dag_forward_by_deadlines(
    log: &[PairRecord],
    capacity: usize,
    deadline: &[usize],
) -> Vec<Vec<usize>> {
    assert_eq!(log.len(), deadline.len());

    let mut successors = vec![Vec::new(); log.len()];
    let mut indegree = vec![0usize; log.len()];
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            successors[parent as usize].push(node);
            indegree[node] += 1;
        }
    }
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut ready = BinaryHeap::new();
    for node in 0..log.len() {
        if indegree[node] == 0 {
            ready.push((Reverse(deadline[node]), Reverse(node)));
        }
    }
    let mut scheduled = 0usize;
    let mut rounds = Vec::new();
    while scheduled < log.len() {
        assert!(!ready.is_empty(), "multiplication graph must be acyclic");
        let mut round = Vec::with_capacity(capacity.min(ready.len()));
        for _ in 0..capacity {
            let Some((_, Reverse(node))) = ready.pop() else {
                break;
            };
            round.push(node);
        }
        scheduled += round.len();
        for &node in &round {
            for &successor in &successors[node] {
                indegree[successor] -= 1;
                if indegree[successor] == 0 {
                    ready.push((Reverse(deadline[successor]), Reverse(successor)));
                }
            }
        }
        rounds.push(round);
    }
    rounds
}

#[derive(Debug, Clone, Copy)]
enum DagListPriority {
    BottomSourceAscending,
    BottomHighFanout,
    BottomSuccessorPressure,
}

/// Deterministic priority variants used to challenge the production list
/// schedule against the same legal DAG. This is intentionally generic: no
/// source-function, AES, or lane identities participate in a priority.
fn dag_priority_list_schedule(
    log: &[PairRecord],
    capacity: usize,
    priority: DagListPriority,
) -> (Vec<Vec<usize>>, Vec<usize>) {
    assert!(capacity > 0);
    let mut successors = vec![Vec::new(); log.len()];
    let mut indegree = vec![0usize; log.len()];
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            successors[parent as usize].push(node);
            indegree[node] += 1;
        }
    }
    let mut bottom = vec![1usize; log.len()];
    for node in (0..log.len()).rev() {
        bottom[node] = 1 + successors[node]
            .iter()
            .map(|&successor| bottom[successor])
            .max()
            .unwrap_or(0);
    }
    let original_indegree = indegree.clone();
    let successor_pressure: Vec<_> = successors
        .iter()
        .map(|children| {
            children
                .iter()
                .map(|&child| 1024 / original_indegree[child].max(1))
                .sum::<usize>()
        })
        .collect();
    let key = |node: usize| {
        let ascending = usize::MAX - node;
        match priority {
            DagListPriority::BottomSourceAscending => (bottom[node], 0, 0, ascending),
            DagListPriority::BottomHighFanout => {
                (bottom[node], successors[node].len(), 0, ascending)
            }
            DagListPriority::BottomSuccessorPressure => {
                (bottom[node], successor_pressure[node], 0, ascending)
            }
        }
    };

    let mut ready = std::collections::BinaryHeap::new();
    for node in 0..log.len() {
        if indegree[node] == 0 {
            ready.push((key(node), node));
        }
    }
    let mut rounds = Vec::new();
    let mut ready_counts = Vec::new();
    let mut scheduled = 0usize;
    while scheduled < log.len() {
        assert!(!ready.is_empty(), "multiplication graph must be acyclic");
        ready_counts.push(ready.len());
        let mut round = Vec::with_capacity(capacity.min(ready.len()));
        for _ in 0..capacity {
            let Some((_, node)) = ready.pop() else {
                break;
            };
            round.push(node);
        }
        scheduled += round.len();
        for &node in &round {
            for &successor in &successors[node] {
                indegree[successor] -= 1;
                if indegree[successor] == 0 {
                    ready.push((key(successor), successor));
                }
            }
        }
        rounds.push(round);
    }
    (rounds, ready_counts)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowCapacityWitness {
    /// Candidate schedule length disproved by this witness.
    horizon: usize,
    /// Inclusive interval of online rounds that must contain `forced_work`.
    first_round: usize,
    last_round: usize,
    forced_work: usize,
    interval_capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PivotCapacityWitness {
    pivot: usize,
    ancestors: usize,
    descendants: usize,
    lower_bound: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainPartitionWitness {
    lower_bound: usize,
    /// Multiplication node ids used as ordered separator pivots.
    pivots: Vec<usize>,
}

/// Capacity/depth lower bound obtained by partitioning the DAG around an
/// ordered chain of multiplication pivots.
///
/// For pivots `p < q`, every node that is both a descendant of `p` and an
/// ancestor of `q` must execute strictly between their rounds. Different
/// consecutive pivot intervals are disjoint. Each interval therefore needs at
/// least the larger of its capacity work bound and its chain-depth bound; the
/// same argument applies before the first and after the last pivot. Dynamic
/// programming chooses the strongest partition of one critical chain.
fn critical_chain_partition_lower_bound(
    log: &[PairRecord],
    capacity: usize,
) -> ChainPartitionWitness {
    assert!(!log.is_empty());
    assert!(capacity > 0);

    let mut pivot = log
        .iter()
        .max_by_key(|record| record.depth)
        .expect("non-empty multiplication log")
        .pair_id as usize;
    let mut chain = vec![pivot];
    while let Some(parent) = log[pivot]
        .parents
        .iter()
        .copied()
        .max_by_key(|&parent| log[parent as usize].depth)
    {
        pivot = parent as usize;
        chain.push(pivot);
    }
    chain.reverse();
    let chain_len = chain.len();
    assert_eq!(
        chain_len,
        log.iter().map(|record| record.depth).max().unwrap() as usize,
        "chosen parent path must realize the recorded critical depth"
    );

    let none = chain_len;
    let mut chain_index = vec![none; log.len()];
    for (index, &node) in chain.iter().enumerate() {
        chain_index[node] = index;
    }

    // Greatest chain pivot known to precede each node (a chain-prefix label).
    let mut latest_ancestor = vec![none; log.len()];
    for node in 0..log.len() {
        let mut latest = chain_index[node];
        for &parent in &log[node].parents {
            let parent_latest = latest_ancestor[parent as usize];
            if parent_latest != none && (latest == none || parent_latest > latest) {
                latest = parent_latest;
            }
        }
        latest_ancestor[node] = latest;
    }

    // Earliest chain pivot known to succeed each node (a chain-suffix label).
    // Reverse topological propagation avoids materializing a second successor
    // graph for the large measured circuits.
    let mut earliest_descendant = chain_index.clone();
    for node in (0..log.len()).rev() {
        let earliest = earliest_descendant[node];
        if earliest == none {
            continue;
        }
        for &parent in &log[node].parents {
            let parent = parent as usize;
            earliest_descendant[parent] = earliest_descendant[parent].min(earliest);
        }
    }

    let stride = chain_len + 1;
    let cell = |row: usize, column: usize| row * stride + column;
    let mut between = vec![0usize; stride * stride];
    let mut ancestors_through = vec![0usize; chain_len];
    let mut descendants_from = vec![0usize; chain_len];
    for node in 0..log.len() {
        let latest = latest_ancestor[node];
        let earliest = earliest_descendant[node];
        if latest != none && earliest != none {
            between[cell(latest, earliest)] += 1;
        }
        if earliest != none {
            ancestors_through[earliest] += 1;
        }
        if latest != none {
            descendants_from[latest] += 1;
        }
    }
    for index in 1..chain_len {
        ancestors_through[index] += ancestors_through[index - 1];
    }
    for index in (0..chain_len.saturating_sub(1)).rev() {
        descendants_from[index] += descendants_from[index + 1];
    }
    // Query count(latest_ancestor >= i && earliest_descendant <= j).
    for latest in (0..chain_len).rev() {
        for earliest in 0..chain_len {
            let below = (latest + 1 < chain_len).then(|| between[cell(latest + 1, earliest)]);
            let left = (earliest > 0).then(|| between[cell(latest, earliest - 1)]);
            let diagonal = (latest + 1 < chain_len && earliest > 0)
                .then(|| between[cell(latest + 1, earliest - 1)]);
            between[cell(latest, earliest)] =
                between[cell(latest, earliest)] + below.unwrap_or(0) + left.unwrap_or(0)
                    - diagonal.unwrap_or(0);
        }
    }

    let mut best_through = vec![0usize; chain_len];
    let mut predecessor = vec![None; chain_len];
    for last in 0..chain_len {
        let strict_ancestors = ancestors_through[last] - 1;
        best_through[last] = last.max(strict_ancestors.div_ceil(capacity)) + 1;
        for previous in 0..last {
            let strict_interior = between[cell(previous, last)] - 2;
            let interval_rounds = (last - previous - 1).max(strict_interior.div_ceil(capacity));
            let candidate = best_through[previous] + interval_rounds + 1;
            if candidate > best_through[last] {
                best_through[last] = candidate;
                predecessor[last] = Some(previous);
            }
        }
    }

    let (mut last, lower_bound) = (0..chain_len)
        .map(|last| {
            let strict_descendants = descendants_from[last] - 1;
            let suffix_rounds = (chain_len - last - 1).max(strict_descendants.div_ceil(capacity));
            (last, best_through[last] + suffix_rounds)
        })
        .max_by_key(|(_, bound)| *bound)
        .expect("critical chain is non-empty");
    let mut pivots = vec![chain[last]];
    while let Some(previous) = predecessor[last] {
        last = previous;
        pivots.push(chain[last]);
    }
    pivots.reverse();
    ChainPartitionWitness {
        lower_bound,
        pivots,
    }
}

/// Resource lower bound around one precedence pivot. Every strict ancestor of
/// `v` must occupy a round before `v`, and every strict descendant must occupy a
/// round after it. Those three regions are disjoint, so
///
///   ceil(|anc(v)| / capacity) + 1 + ceil(|desc(v)| / capacity)
///
/// is a sound makespan lower bound. We evaluate every node on one longest chain;
/// this is inexpensive for the large AES-family DAGs and each returned witness
/// remains independently checkable without trusting the candidate selection.
fn critical_chain_pivot_lower_bound(log: &[PairRecord], capacity: usize) -> PivotCapacityWitness {
    assert!(!log.is_empty());
    assert!(capacity > 0);
    let mut successors = vec![Vec::new(); log.len()];
    for record in log {
        for &parent in &record.parents {
            successors[parent as usize].push(record.pair_id as usize);
        }
    }

    let mut pivot = log
        .iter()
        .max_by_key(|record| record.depth)
        .expect("non-empty multiplication log")
        .pair_id as usize;
    let mut chain = vec![pivot];
    while let Some(parent) = log[pivot]
        .parents
        .iter()
        .copied()
        .max_by_key(|&parent| log[parent as usize].depth)
    {
        pivot = parent as usize;
        chain.push(pivot);
    }

    let mut visited = vec![0u32; log.len()];
    let mut generation = 0u32;
    let mut count_reachable = |root: usize, reverse: bool| {
        generation = generation.wrapping_add(1);
        if generation == 0 {
            visited.fill(0);
            generation = 1;
        }
        let mut count = 0usize;
        let mut pending = Vec::new();
        if reverse {
            pending.extend(log[root].parents.iter().map(|&parent| parent as usize));
        } else {
            pending.extend(successors[root].iter().copied());
        }
        while let Some(node) = pending.pop() {
            if visited[node] == generation {
                continue;
            }
            visited[node] = generation;
            count += 1;
            if reverse {
                pending.extend(log[node].parents.iter().map(|&parent| parent as usize));
            } else {
                pending.extend(successors[node].iter().copied());
            }
        }
        count
    };

    chain
        .into_iter()
        .map(|pivot| {
            let ancestors = count_reachable(pivot, true);
            let descendants = count_reachable(pivot, false);
            PivotCapacityWitness {
                pivot,
                ancestors,
                descendants,
                lower_bound: ancestors.div_ceil(capacity) + 1 + descendants.div_ceil(capacity),
            }
        })
        .max_by_key(|witness| witness.lower_bound)
        .expect("critical chain contains a pivot")
}

/// Return a precedence/capacity certificate that `horizon` multiply rounds are
/// impossible, when the standard earliest/latest time-window relaxation can
/// prove it.
///
/// For every unit-time multiplication `v`, `top[v]` is its earliest legal round
/// and `horizon - bottom[v] + 1` is its latest legal round. Therefore every node
/// whose complete legal window is contained in `[a, b]` is forced to execute in
/// that interval. More than `capacity * (b - a + 1)` such nodes is a sound
/// contradiction for *every* scheduler, independent of source order or the
/// heuristic used to construct the observed schedule.
fn window_capacity_witness(
    log: &[PairRecord],
    capacity: usize,
    horizon: usize,
) -> Option<WindowCapacityWitness> {
    assert!(capacity > 0);
    if log.is_empty() {
        return None;
    }

    let mut successors = vec![Vec::new(); log.len()];
    let mut top = vec![1usize; log.len()];
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            successors[parent as usize].push(node);
            top[node] = top[node].max(top[parent as usize] + 1);
        }
    }
    let mut bottom = vec![1usize; log.len()];
    for node in (0..log.len()).rev() {
        bottom[node] = 1 + successors[node]
            .iter()
            .map(|&successor| bottom[successor])
            .max()
            .unwrap_or(0);
    }

    window_capacity_witness_for_bounds(&top, &bottom, capacity, horizon)
}

/// Earliest possible completion round for unit jobs with individual release
/// rounds on `capacity` identical lanes. Dependencies among those jobs are
/// deliberately ignored, making this a relaxation and therefore a lower bound.
fn released_work_completion_round(
    release_rounds: impl Iterator<Item = usize>,
    capacity: usize,
) -> usize {
    let mut releases: Vec<_> = release_rounds.collect();
    if releases.is_empty() {
        return 0;
    }
    releases.sort_unstable();
    releases
        .iter()
        .enumerate()
        .map(|(index, &release)| release + (releases.len() - index).div_ceil(capacity) - 1)
        .max()
        .expect("non-empty release list")
}

/// Strengthen precedence-only earliest/latest rounds with capacity-aware
/// release-time facts. Every predecessor of `v` must finish before `v`; even
/// after dependencies among those predecessors are relaxed away, their own
/// earliest rounds and the finite lane count impose a minimum completion time.
/// The reverse statement holds for successors. This is stronger than merely
/// counting fan-in/fan-out and remains a scheduler-independent lower bound.
fn resource_window_capacity_witness(
    log: &[PairRecord],
    capacity: usize,
    horizon: usize,
) -> Option<WindowCapacityWitness> {
    assert!(capacity > 0);
    if log.is_empty() {
        return None;
    }

    let mut successors = vec![Vec::new(); log.len()];
    let mut top = vec![1usize; log.len()];
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            let parent = parent as usize;
            successors[parent].push(node);
        }
        if !record.parents.is_empty() {
            top[node] = released_work_completion_round(
                record.parents.iter().map(|&parent| top[parent as usize]),
                capacity,
            ) + 1;
        }
    }
    let mut bottom = vec![1usize; log.len()];
    for node in (0..log.len()).rev() {
        if !successors[node].is_empty() {
            bottom[node] = released_work_completion_round(
                successors[node].iter().map(|&successor| bottom[successor]),
                capacity,
            ) + 1;
        }
    }

    window_capacity_witness_for_bounds(&top, &bottom, capacity, horizon)
}

fn window_capacity_witness_for_bounds(
    top: &[usize],
    bottom: &[usize],
    capacity: usize,
    horizon: usize,
) -> Option<WindowCapacityWitness> {
    assert_eq!(top.len(), bottom.len());

    // A node with an empty legal window is itself a critical-path certificate.
    for node in 0..top.len() {
        let Some(latest) = horizon.checked_sub(bottom[node]).map(|v| v + 1) else {
            return Some(WindowCapacityWitness {
                horizon,
                first_round: top[node],
                last_round: top[node],
                forced_work: 1,
                interval_capacity: 0,
            });
        };
        if top[node] > latest {
            return Some(WindowCapacityWitness {
                horizon,
                first_round: latest,
                last_round: top[node],
                forced_work: 1,
                interval_capacity: 0,
            });
        }
    }

    // grid[earliest][latest] counts jobs with that complete legal window. The
    // two-dimensional suffix/prefix sum below answers
    //   count(earliest >= a && latest <= b)
    // in O(1), allowing every interval to be checked in O(horizon^2).
    let stride = horizon + 2;
    let mut forced = vec![0usize; stride * stride];
    let cell = |row: usize, column: usize| row * stride + column;
    for node in 0..top.len() {
        let latest = horizon - bottom[node] + 1;
        forced[cell(top[node], latest)] += 1;
    }
    for earliest in (1..=horizon).rev() {
        for latest in 1..=horizon {
            forced[cell(earliest, latest)] = forced[cell(earliest, latest)]
                + forced[cell(earliest + 1, latest)]
                + forced[cell(earliest, latest - 1)]
                - forced[cell(earliest + 1, latest - 1)];
        }
    }

    let mut strongest = None;
    for first_round in 1..=horizon {
        for last_round in first_round..=horizon {
            let forced_work = forced[cell(first_round, last_round)];
            let interval_capacity = capacity * (last_round - first_round + 1);
            if forced_work > interval_capacity
                && strongest.is_none_or(|prior: WindowCapacityWitness| {
                    forced_work - interval_capacity > prior.forced_work - prior.interval_capacity
                })
            {
                strongest = Some(WindowCapacityWitness {
                    horizon,
                    first_round,
                    last_round,
                    forced_work,
                    interval_capacity,
                });
            }
        }
    }
    strongest
}

/// Strongest sound lower bound obtained by disproving candidate horizons with
/// precedence time-window density. `legal_upper_bound` is an already-validated
/// schedule, so the result can never exceed it.
fn window_capacity_lower_bound(
    log: &[PairRecord],
    capacity: usize,
    legal_upper_bound: usize,
) -> (usize, Option<WindowCapacityWitness>) {
    let critical_path = validate_pair_dag(log);
    let work_bound = log.len().div_ceil(capacity);
    let basic_bound = critical_path.max(work_bound);
    let mut lower_bound = basic_bound;
    let mut strongest_witness = None;
    for horizon in basic_bound..legal_upper_bound {
        if let Some(witness) = window_capacity_witness(log, capacity, horizon) {
            lower_bound = lower_bound.max(horizon + 1);
            strongest_witness = Some(witness);
        }
    }
    (lower_bound, strongest_witness)
}

/// Strongest sound lower bound obtained from the resource-strengthened
/// earliest/latest windows. Keep this separate from the precedence-only bound
/// while the stronger relaxation is exercised against the exact oracle.
fn resource_window_capacity_lower_bound(
    log: &[PairRecord],
    capacity: usize,
    legal_upper_bound: usize,
) -> (usize, Option<WindowCapacityWitness>) {
    let critical_path = validate_pair_dag(log);
    let work_bound = log.len().div_ceil(capacity);
    let basic_bound = critical_path.max(work_bound);
    let mut lower_bound = basic_bound;
    let mut strongest_witness = None;
    for horizon in basic_bound..legal_upper_bound {
        if let Some(witness) = resource_window_capacity_witness(log, capacity, horizon) {
            lower_bound = lower_bound.max(horizon + 1);
            strongest_witness = Some(witness);
        }
    }
    (lower_bound, strongest_witness)
}

/// A legal capacity-aware schedule that keeps each already-executed protocol
/// chunk atomic. This is an intermediate oracle between the observed source
/// order and the lane-level DAG schedule: any improvement it finds needs only
/// chunk reordering/repacking, while the remaining gap requires splitting
/// existing chunks into lane slices.
fn call_dag_list_schedule(log: &[PairRecord], capacity: usize) -> Vec<Vec<usize>> {
    assert!(capacity > 0);
    let Some(last_call) = log.iter().map(|record| record.call_id as usize).max() else {
        return Vec::new();
    };
    let call_count = last_call + 1;
    let mut work = vec![0usize; call_count];
    let mut successors = vec![std::collections::HashSet::new(); call_count];
    let mut indegree = vec![0usize; call_count];
    for record in log {
        let call = record.call_id as usize;
        work[call] += 1;
        for &parent in &record.parents {
            let parent_call = log[parent as usize].call_id as usize;
            if parent_call != call && successors[parent_call].insert(call) {
                indegree[call] += 1;
            }
        }
    }
    assert!(
        work.iter().all(|&items| items > 0 && items <= capacity),
        "recorded protocol chunks must be non-empty and capacity-bounded"
    );

    let mut bottom_level = vec![1usize; call_count];
    for call in (0..call_count).rev() {
        bottom_level[call] = 1 + successors[call]
            .iter()
            .map(|&successor| bottom_level[successor])
            .max()
            .unwrap_or(0);
    }

    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut ready = BinaryHeap::new();
    for call in 0..call_count {
        if indegree[call] == 0 {
            ready.push((bottom_level[call], Reverse(call)));
        }
    }
    let mut rounds = Vec::new();
    let mut scheduled = 0usize;
    while scheduled < call_count {
        assert!(!ready.is_empty(), "call dependency graph must be acyclic");
        let (_, Reverse(first)) = ready.pop().expect("ready call");
        let mut round = vec![first];
        let mut remaining = capacity - work[first];
        let mut deferred = Vec::new();
        while let Some(entry @ (_, Reverse(call))) = ready.pop() {
            if work[call] <= remaining {
                round.push(call);
                remaining -= work[call];
            } else {
                deferred.push(entry);
            }
        }
        ready.extend(deferred);

        scheduled += round.len();
        for &call in &round {
            for &successor in &successors[call] {
                indegree[successor] -= 1;
                if indegree[successor] == 0 {
                    ready.push((bottom_level[successor], Reverse(successor)));
                }
            }
        }
        rounds.push(round);
    }
    rounds
}

/// Number of contiguous source-call slices needed to encode `schedule` without
/// scalarizing every multiply lane. A segment continues only while pair ids are
/// adjacent and came from the same original protocol call.
fn scheduled_source_segments(log: &[PairRecord], schedule: &[Vec<usize>]) -> (usize, usize) {
    let mut total = 0usize;
    let mut max_per_round = 0usize;
    for round in schedule {
        let mut ordered = round.clone();
        ordered.sort_unstable();
        let mut segments = 0usize;
        let mut previous = None;
        for node in ordered {
            let starts_segment = previous.is_none_or(|prior: usize| {
                node != prior + 1 || log[node].call_id != log[prior].call_id
            });
            if starts_segment {
                segments += 1;
            }
            previous = Some(node);
        }
        total += segments;
        max_per_round = max_per_round.max(segments);
    }
    (total, max_per_round)
}

/// A legality-preserving schedule that prefers whole contiguous ready runs from
/// the original protocol calls. This measures the round/encoding tradeoff of a
/// compact slice-based lowering; it is diagnostic and does not define the
/// optimizer's correctness bound.
fn dag_source_clustered_schedule(log: &[PairRecord], capacity: usize) -> Vec<Vec<usize>> {
    assert!(capacity > 0);
    let mut successors = vec![Vec::new(); log.len()];
    let mut indegree = vec![0usize; log.len()];
    for record in log {
        let node = record.pair_id as usize;
        for &parent in &record.parents {
            successors[parent as usize].push(node);
            indegree[node] += 1;
        }
    }
    let mut bottom_level = vec![1usize; log.len()];
    for node in (0..log.len()).rev() {
        bottom_level[node] = 1 + successors[node]
            .iter()
            .map(|&successor| bottom_level[successor])
            .max()
            .unwrap_or(0);
    }

    let mut ready: std::collections::BTreeSet<usize> =
        (0..log.len()).filter(|&node| indegree[node] == 0).collect();
    let mut schedule = Vec::new();
    let mut scheduled = 0usize;
    while scheduled < log.len() {
        assert!(!ready.is_empty(), "multiplication graph must be acyclic");
        let mut round = Vec::with_capacity(capacity.min(ready.len()));
        while round.len() < capacity && !ready.is_empty() {
            let seed = *ready
                .iter()
                .max_by_key(|&&node| (bottom_level[node], std::cmp::Reverse(node)))
                .expect("ready is non-empty");
            ready.remove(&seed);
            round.push(seed);

            // Consume the rest of the seed's contiguous ready source run. The
            // round boundary remains sound because successors are released only
            // after the complete round below.
            let call = log[seed].call_id;
            let mut left = seed;
            while round.len() < capacity && left > 0 {
                let next = left - 1;
                if log[next].call_id != call || !ready.remove(&next) {
                    break;
                }
                round.push(next);
                left = next;
            }
            let mut right = seed + 1;
            while round.len() < capacity
                && right < log.len()
                && log[right].call_id == call
                && ready.remove(&right)
            {
                round.push(right);
                right += 1;
            }
        }
        scheduled += round.len();
        for &node in &round {
            for &successor in &successors[node] {
                indegree[successor] -= 1;
                if indegree[successor] == 0 {
                    ready.insert(successor);
                }
            }
        }
        schedule.push(round);
    }
    schedule
}

/// Exact minimum number of capacity-limited rounds for a small unit-time DAG.
/// Used as a scheduler oracle in regression/property tests; exponential by
/// design and deliberately limited to at most 63 nodes.
fn exact_min_rounds(parents: &[u64], capacity: usize) -> usize {
    assert!(!parents.is_empty());
    assert!(parents.len() <= 63);
    assert!(capacity > 0);
    let all = (1u64 << parents.len()) - 1;
    let mut memo = std::collections::HashMap::new();

    fn solve(
        done: u64,
        all: u64,
        parents: &[u64],
        capacity: usize,
        memo: &mut std::collections::HashMap<u64, usize>,
    ) -> usize {
        if done == all {
            return 0;
        }
        if let Some(&cached) = memo.get(&done) {
            return cached;
        }
        let mut ready = 0u64;
        for (node, &deps) in parents.iter().enumerate() {
            let bit = 1u64 << node;
            if done & bit == 0 && deps & !done == 0 {
                ready |= bit;
            }
        }
        assert_ne!(ready, 0, "input must be an acyclic graph");

        let ready_count = ready.count_ones() as usize;
        let mut best = usize::MAX;
        if ready_count <= capacity {
            best = 1 + solve(done | ready, all, parents, capacity, memo);
        } else {
            // An optimal unit-task schedule can be work-conserving. Enumerate
            // every capacity-sized choice from the ready set; choice still
            // matters because different nodes unlock different successors.
            fn choose(candidates: u64, need: usize, picked: u64, visit: &mut impl FnMut(u64)) {
                if need == 0 {
                    visit(picked);
                    return;
                }
                if (candidates.count_ones() as usize) < need {
                    return;
                }
                let bit = candidates & candidates.wrapping_neg();
                let rest = candidates ^ bit;
                choose(rest, need - 1, picked | bit, visit);
                choose(rest, need, picked, visit);
            }
            choose(ready, capacity, 0, &mut |round| {
                best = best.min(1 + solve(done | round, all, parents, capacity, memo));
            });
        }
        memo.insert(done, best);
        best
    }

    solve(0, all, parents, capacity, &mut memo)
}

impl CountingEngine {
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.scalar_mul_calls.load(Ordering::SeqCst),
            self.batch_mul_calls.load(Ordering::SeqCst),
            self.batch_mul_items.load(Ordering::SeqCst),
        )
    }

    fn protocol_rounds(&self) -> usize {
        self.call_seq.load(Ordering::SeqCst)
    }

    fn open_protocol_rounds(&self) -> usize {
        self.open_rounds.load(Ordering::SeqCst)
    }

    fn open_protocol_breakdown(&self) -> (usize, usize) {
        (
            self.scalar_open_rounds.load(Ordering::SeqCst),
            self.batch_open_rounds.load(Ordering::SeqCst),
        )
    }

    fn record_scalar_open_round(&self) {
        self.open_rounds.fetch_add(1, Ordering::SeqCst);
        self.scalar_open_rounds.fetch_add(1, Ordering::SeqCst);
    }

    fn record_batch_open_round(&self) {
        self.open_rounds.fetch_add(1, Ordering::SeqCst);
        self.batch_open_rounds.fetch_add(1, Ordering::SeqCst);
    }

    /// (public_operand_muls, both_public_muls, max_mul_depth) — see field docs.
    fn lever_b_counts(&self) -> (usize, usize, usize) {
        (
            self.public_operand_muls.load(Ordering::SeqCst),
            self.both_public_muls.load(Ordering::SeqCst),
            self.max_mul_depth.load(Ordering::SeqCst),
        )
    }

    /// Snapshot of every executed multiply pair (for the per-depth histogram).
    fn pair_log_snapshot(&self) -> Vec<PairRecord> {
        self.pair_log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    fn bool_byte(bytes: &[u8]) -> u8 {
        bytes.first().copied().unwrap_or_default() & 1
    }

    // --- Share metadata layout -------------------------------------------------
    // Every share this engine emits is
    // `[value, public, d0..d3, parent_count0..3, parent_ids...]`:
    //   byte 0      : the GF(2) value bit (read by `bool_byte`, unchanged).
    //   byte 1      : public-literal taint flag (1 = traces to a literal through
    //                 only local ops).
    //   bytes 2..6  : critical-path multiply depth as u32 little-endian.
    // Legacy 1-byte shares (e.g. raw client inputs) decode as public=false,
    // depth=0, which is the correct default for a secret input.
    fn pack(value: u8, public: bool, depth: u32, frontier: &[u32]) -> Vec<u8> {
        let d = depth.to_le_bytes();
        let count = (frontier.len() as u32).to_le_bytes();
        let mut packed = Vec::with_capacity(10 + frontier.len() * 4);
        packed.extend_from_slice(&[value & 1, u8::from(public), d[0], d[1], d[2], d[3]]);
        packed.extend_from_slice(&count);
        for parent in frontier {
            packed.extend_from_slice(&parent.to_le_bytes());
        }
        packed
    }

    fn is_public(bytes: &[u8]) -> bool {
        bytes.get(1).copied().unwrap_or(0) != 0
    }

    fn depth_of(bytes: &[u8]) -> u32 {
        if bytes.len() >= 6 {
            u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]])
        } else {
            0
        }
    }

    fn frontier_of(bytes: &[u8]) -> Vec<u32> {
        if bytes.len() < 10 {
            return Vec::new();
        }
        let count = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        let available = bytes.len().saturating_sub(10) / 4;
        let mut frontier = Vec::with_capacity(count.min(available));
        for chunk in bytes[10..].chunks_exact(4).take(count) {
            frontier.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        frontier
    }

    fn merged_frontier(left: &[u8], right: &[u8]) -> Vec<u32> {
        let mut frontier = Self::frontier_of(left);
        frontier.extend(Self::frontier_of(right));
        frontier.sort_unstable();
        frontier.dedup();
        frontier
    }

    /// Execute one secret multiply `ab`: compute its value, record lever-B and
    /// depth instrumentation, and return packed metadata for the product (a
    /// product remains provably public when both operands are public, even if
    /// the current compiler unnecessarily executes it interactively. Preserving
    /// that fact exposes the complete downstream localization opportunity.
    /// Shared by scalar/async/batch paths.
    fn record_multiply(&self, call_id: u32, left: &[u8], right: &[u8]) -> Vec<u8> {
        let value = Self::bool_byte(left) & Self::bool_byte(right);
        let out_depth = Self::depth_of(left).max(Self::depth_of(right)) + 1;
        self.max_mul_depth
            .fetch_max(out_depth as usize, Ordering::SeqCst);
        let left_pub = Self::is_public(left);
        let right_pub = Self::is_public(right);
        if left_pub || right_pub {
            self.public_operand_muls.fetch_add(1, Ordering::SeqCst);
        }
        if left_pub && right_pub {
            self.both_public_muls.fetch_add(1, Ordering::SeqCst);
        }
        let pair_id = self.pair_seq.fetch_add(1, Ordering::SeqCst) as u32;
        let parents = Self::merged_frontier(left, right);
        if let Ok(mut log) = self.pair_log.lock() {
            log.push(PairRecord {
                pair_id,
                parents,
                call_id,
                depth: out_depth,
                pub_operand: left_pub || right_pub,
                both_public: left_pub && right_pub,
            });
        }
        Self::pack(value, left_pub && right_pub, out_depth, &[pair_id])
    }

    /// Allocate a fresh round id for one multiply call (scalar or batch).
    fn next_call_id(&self) -> u32 {
        self.call_seq.fetch_add(1, Ordering::SeqCst) as u32
    }

    fn share_from_clear(clear: ClearShareInput) -> ShareData {
        let byte = match clear.value() {
            ClearShareValue::Integer(value) => (value & 1) as u8,
            ClearShareValue::UnsignedInteger(value) => (value & 1) as u8,
            ClearShareValue::FixedPoint(value) => ((value.0 as i64) & 1) as u8,
            ClearShareValue::Boolean(value) => u8::from(value),
        };
        // A `from_clear` value is a compile-time public literal: public=true, depth 0.
        ShareData::Opaque(Self::pack(byte, true, 0, &[]).into())
    }

    fn open_bool(share_bytes: &[u8]) -> ClearShareValue {
        ClearShareValue::Boolean(Self::bool_byte(share_bytes) != 0)
    }
}

impl MpcEngine for CountingEngine {
    fn protocol_name(&self) -> &'static str {
        "counting"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(1, 0, 1, 0).expect("valid counting topology")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn multiplication_batch_capacity(&self) -> Option<usize> {
        Some(MODELED_MPC_BATCH_CAPACITY)
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_from_clear(clear))
    }

    fn open_share(&self, _ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        self.record_scalar_open_round();
        Ok(Self::open_bool(share_bytes))
    }

    fn batch_open_shares(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        if !shares.is_empty() {
            self.record_batch_open_round();
        }
        Ok(shares.iter().map(|share| Self::open_bool(share)).collect())
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn add_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        // Local linear op: public iff both operands public; depth = max of inputs.
        let value = Self::bool_byte(lhs_bytes) ^ Self::bool_byte(rhs_bytes);
        let public = Self::is_public(lhs_bytes) && Self::is_public(rhs_bytes);
        let depth = Self::depth_of(lhs_bytes).max(Self::depth_of(rhs_bytes));
        Ok(Self::pack(
            value,
            public,
            depth,
            &Self::merged_frontier(lhs_bytes, rhs_bytes),
        ))
    }

    fn sub_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = Self::bool_byte(lhs_bytes) ^ Self::bool_byte(rhs_bytes);
        let public = Self::is_public(lhs_bytes) && Self::is_public(rhs_bytes);
        let depth = Self::depth_of(lhs_bytes).max(Self::depth_of(rhs_bytes));
        Ok(Self::pack(
            value,
            public,
            depth,
            &Self::merged_frontier(lhs_bytes, rhs_bytes),
        ))
    }

    fn neg_share_local(&self, _ty: ShareType, share_bytes: &[u8]) -> ShareAlgebraResult<Vec<u8>> {
        // GF(2) negation == identity on the value; metadata is preserved.
        Ok(Self::pack(
            Self::bool_byte(share_bytes),
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
            &Self::frontier_of(share_bytes),
        ))
    }

    fn mul_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        // Scalar (public constant) factor: keeps publicness and depth of the share.
        let value = Self::bool_byte(share_bytes) & ((scalar & 1) as u8);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
            &Self::frontier_of(share_bytes),
        ))
    }

    fn add_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = Self::bool_byte(share_bytes) ^ ((scalar & 1) as u8);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
            &Self::frontier_of(share_bytes),
        ))
    }

    fn sub_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = Self::bool_byte(share_bytes) ^ ((scalar & 1) as u8);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
            &Self::frontier_of(share_bytes),
        ))
    }

    fn scalar_sub_share_local(
        &self,
        _ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        let value = ((scalar & 1) as u8) ^ Self::bool_byte(share_bytes);
        Ok(Self::pack(
            value,
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
            &Self::frontier_of(share_bytes),
        ))
    }

    fn div_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        assert_ne!(scalar & 1, 0, "division by zero in GF(2)");
        Ok(Self::pack(
            Self::bool_byte(share_bytes),
            Self::is_public(share_bytes),
            Self::depth_of(share_bytes),
            &Self::frontier_of(share_bytes),
        ))
    }
}

impl MpcEngineMultiplication for CountingEngine {
    fn multiply_share(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        let call_id = self.next_call_id();
        Ok(ShareData::Opaque(
            self.record_multiply(call_id, left, right).into(),
        ))
    }
}

#[async_trait::async_trait]
impl stoffel_vm::net::mpc_engine::AsyncMpcEngine for CountingEngine {
    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_from_clear(clear))
    }

    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        let call_id = self.next_call_id();
        Ok(ShareData::Opaque(
            self.record_multiply(call_id, left, right).into(),
        ))
    }

    async fn batch_multiply_share_async(
        &self,
        _ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> MpcEngineResult<Vec<ShareData>> {
        self.batch_mul_calls.fetch_add(1, Ordering::SeqCst);
        self.batch_mul_items
            .fetch_add(pairs.len(), Ordering::SeqCst);
        let mut products = Vec::with_capacity(pairs.len());
        for chunk in pairs.chunks(MODELED_MPC_BATCH_CAPACITY) {
            let call_id = self.next_call_id();
            products.extend(chunk.iter().map(|(left, right)| {
                ShareData::Opaque(self.record_multiply(call_id, left, right).into())
            }));
        }
        Ok(products)
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        self.record_scalar_open_round();
        Ok(Self::open_bool(share_bytes))
    }

    async fn batch_open_shares_async(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        if !shares.is_empty() {
            self.record_batch_open_round();
        }
        Ok(shares.iter().map(|share| Self::open_bool(share)).collect())
    }

    async fn random_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0].into()))
    }

    async fn random_integer_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0].into()))
    }
}

/// Compiling and executing the optimized AES circuit recurses deeply (the
/// inlined S-box network and the VM interpreter), which overflows the default
/// ~2 MB cargo/tokio test-thread stack on some platforms. Run the work on a
/// dedicated large-stack thread with its own runtime.
fn run_on_large_stack<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(256 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime")
                .block_on(future);
        })
        .expect("spawn large-stack test thread")
        .join()
        .expect("large-stack test thread panicked");
}

#[test]
fn exact_capacity_scheduler_oracle_handles_precedence_and_choices() {
    assert_eq!(exact_min_rounds(&[0, 0, 0, 0, 0], 2), 3);
    assert_eq!(exact_min_rounds(&[0, 1 << 0, 1 << 1, 1 << 2], 2), 4);
    assert_eq!(
        exact_min_rounds(&[0, 1 << 0, 1 << 0, (1 << 1) | (1 << 2)], 2),
        3
    );

    // Three roots compete for two slots. Scheduling node 0 immediately unlocks
    // a two-node chain and finishes in three rounds; choosing roots 1+2 first
    // takes four. The oracle must enumerate ready-set choices, not use a fixed
    // source-order greedy policy.
    assert_eq!(exact_min_rounds(&[0, 0, 0, 1 << 0, 1 << 3], 2), 3);
}

#[test]
fn precedence_window_certificate_is_sound_for_all_five_node_dags() {
    const NODES: usize = 5;
    let possible_edges = NODES * (NODES - 1) / 2;
    let mut strengthened_examples = 0usize;

    for edge_set in 0u64..(1u64 << possible_edges) {
        let mut parents = vec![0u64; NODES];
        let mut edge_index = 0usize;
        for node in 0..NODES {
            for parent in 0..node {
                if edge_set & (1u64 << edge_index) != 0 {
                    parents[node] |= 1u64 << parent;
                }
                edge_index += 1;
            }
        }

        let mut depths = vec![1u32; NODES];
        let log: Vec<_> = parents
            .iter()
            .enumerate()
            .map(|(node, &dependencies)| {
                let parent_ids: Vec<_> = (0..node)
                    .filter(|&parent| dependencies & (1u64 << parent) != 0)
                    .map(|parent| parent as u32)
                    .collect();
                depths[node] = 1 + parent_ids
                    .iter()
                    .map(|&parent| depths[parent as usize])
                    .max()
                    .unwrap_or(0);
                PairRecord {
                    pair_id: node as u32,
                    parents: parent_ids,
                    // Sequential execution is a legal upper-bound schedule for
                    // every topologically numbered graph.
                    call_id: node as u32,
                    depth: depths[node],
                    pub_operand: false,
                    both_public: false,
                }
            })
            .collect();

        for capacity in 1..=NODES {
            let optimum = exact_min_rounds(&parents, capacity);
            assert!(
                window_capacity_witness(&log, capacity, optimum).is_none(),
                "a necessary time-window condition rejected a legal optimum: \
                 edge_set={edge_set:#x}, capacity={capacity}, optimum={optimum}"
            );
            assert!(
                resource_window_capacity_witness(&log, capacity, optimum).is_none(),
                "a resource-strengthened time-window condition rejected a legal optimum: \
                 edge_set={edge_set:#x}, capacity={capacity}, optimum={optimum}"
            );
            let basic = validate_pair_dag(&log).max(NODES.div_ceil(capacity));
            let (window_bound, _) = window_capacity_lower_bound(&log, capacity, optimum);
            let (resource_window_bound, _) =
                resource_window_capacity_lower_bound(&log, capacity, optimum);
            let chain_bound = critical_chain_partition_lower_bound(&log, capacity).lower_bound;
            assert!(
                window_bound <= optimum,
                "time-window lower bound exceeded the exact optimum"
            );
            assert!(
                resource_window_bound <= optimum,
                "resource-strengthened time-window lower bound exceeded the exact optimum"
            );
            assert!(
                chain_bound <= optimum,
                "chain-partition lower bound exceeded the exact optimum: \
                 edge_set={edge_set:#x}, capacity={capacity}, optimum={optimum}, \
                 chain_bound={chain_bound}"
            );
            strengthened_examples +=
                usize::from(window_bound.max(resource_window_bound).max(chain_bound) > basic);
        }
    }

    assert!(
        strengthened_examples > 0,
        "the window certificate should strictly strengthen work/critical-path \
         bounds for at least one small DAG"
    );
}

/// Regression test for the -O3 function inliner: a `secret`-typed helper that is
/// inlined must keep its arguments secret, so the secret `and`/multiply still runs
/// as an MPC multiplication (counted in `batch`/`scalar`) rather than collapsing
/// to a clear bitwise op. We compile the same secret program at -O0 and -O3 and
/// require (a) the revealed result is identical and (b) -O3 still performs a real
/// secret multiplication (a non-zero multiply count) — i.e. secrecy survived
/// inlining. If inlining dropped the secret flag, the `and` would compile to a
/// clear op and the multiply count would drop to zero.
#[test]
fn inlining_preserves_secret_multiplication() {
    run_on_large_stack(inlining_preserves_secret_multiplication_impl());
}

async fn inlining_preserves_secret_multiplication_impl() {
    // `gate_and` is a secret-bool helper (an MPC multiply in GF(2)); `combine`
    // chains two of them so inlining has something to fold. Client shares are
    // deliberately used instead of public `from_clear_int` values: public
    // constants are now correctly localized and would make this secrecy test
    // vacuous for the opposite reason.
    let source = r#"
def gate_and(a: secret bool, b: secret bool) -> secret bool:
  return a and b

def combine(a: secret bool, b: secret bool, c: secret bool) -> secret bool:
  return gate_and(gate_and(a, b), c)

def main() -> int64:
  var x: secret bool = ClientStore.take_share_bool(0, 0)
  var y: secret bool = ClientStore.take_share_bool(0, 1)
  var z: secret bool = ClientStore.take_share_bool(0, 2)
  var w: secret bool = combine(x, y, z)
  var r: bool = w.reveal()
  if r:
    return 1
  return 0
"#;

    let run_at = |level: u8| async move {
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<inline-secrecy>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        vm.store_client_shares(0, bits_as_bool_shares(&[0b0000_0111]));
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let (scalar, _batch_calls, batch_items) = engine.counts();
        (result, scalar + batch_items)
    };

    let (base_result, base_muls) = run_at(0).await;
    let (opt_result, opt_muls) = run_at(3).await;

    assert_eq!(
        base_result, opt_result,
        "-O3 inlining changed the revealed secret result"
    );
    assert!(
        base_muls > 0,
        "baseline should perform secret multiplications (test would be vacuous otherwise)"
    );
    assert!(
        opt_muls > 0,
        "-O3 inlined `gate_and` lost its secret typing: the secret `and` compiled \
         to a clear op (zero MPC multiplications), which is the secrecy bug"
    );
}

#[test]
#[ignore = "counts optimized AES MPC multiplication demand"]
fn count_optimized_aes_batch_mul_items() {
    run_on_large_stack(count_optimized_aes_batch_mul_items_impl());
}

async fn count_optimized_aes_batch_mul_items_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-count>", &options).expect("compile AES");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let _ = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES with counting engine");
    let (scalar, batch_calls, batch_items) = engine.counts();
    // The optimizer must convert EVERY secret multiplication into a batched one
    // (no leftover scalar `multiply_share` calls) and preserve the exact total
    // number of products — these are the real correctness invariants.
    assert_eq!(
        scalar, 0,
        "optimizer should batch every secret multiply; {scalar} ran as scalar"
    );
    assert_eq!(batch_items, 32_679);
    // This test compiles at the default optimization level (no -O3), so the
    // per-byte S-box loops are not unrolled and the round-minimizing scheduler
    // does not run. At this level the optimizer batches independent multiplies
    // only WITHIN each byte's S-box, yielding many smaller batches (~6.3k). At
    // -O3 (see `optimized_aes_at_o3_matches_nist_vector`) length-aware unrolling
    // plus the list scheduler batch across the formerly-separate iterations and
    // cut this to a few thousand rounds. The meaningful guarantee here is just
    // that batching still collapses the ~34k multiplies into far fewer calls.
    assert!(
        batch_calls < batch_items / 4,
        "multiplies should be meaningfully batched, not near one-call-each; \
         got {batch_calls} calls for {batch_items} items"
    );
}

#[test]
fn optimized_aes_matches_nist_vector_with_compiler_spills() {
    run_on_large_stack(optimized_aes_matches_nist_vector_with_compiler_spills_impl());
}

async fn optimized_aes_matches_nist_vector_with_compiler_spills_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-exec>", &options).expect("compile AES");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES with boolean engine");
    let Value::Array(result_ref) = result else {
        panic!("AES main should return an array");
    };

    let mut ciphertext = Vec::new();
    for index in 0..vm.read_array_len(result_ref).expect("ciphertext length") {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .expect("read ciphertext byte")
            .expect("ciphertext byte");
        let Value::I64(byte) = value else {
            panic!("ciphertext byte should be an int64, got {value:?}");
        };
        ciphertext.push(byte);
    }

    assert_eq!(
        ciphertext,
        vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
    );
}

/// Regression test for the ABI-result-register spill bug: at -O3, function
/// inlining turns `aes128_encrypt` into a large zero-parameter function full of
/// `CALL; MOV(dest, 0)` result captures. Register 0 (the ABI result register) has
/// no virtual-register def, so before the fix the allocator spilled it and emitted
/// `LDS` loads with no `STS` — reading an uninitialized `Unit` and failing in a
/// clear/secret conversion (`UnsupportedClearShareValue { value: () }`). Pinning
/// VR0 to physical R0 keeps the result register live and unspilled. This runs the
/// full AES circuit at -O3 (heavy inlining + spilling) and requires the NIST
/// SP 800-38A vector, proving the -O3 pipeline is now both crash-free and correct.
#[test]
fn optimized_aes_at_o3_matches_nist_vector() {
    run_on_large_stack(optimized_aes_at_o3_matches_nist_vector_impl());
}

async fn optimized_aes_at_o3_matches_nist_vector_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        optimization_level: 3,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-o3>", &options).expect("compile AES at -O3");
    let binary = stoffellang::convert_to_binary(&compiled);
    let planned_triples = binary.client_io_manifest.preprocessing_demand.triples;
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES at -O3");
    let Value::Array(result_ref) = result else {
        panic!("AES main should return an array");
    };

    let mut ciphertext = Vec::new();
    for index in 0..vm.read_array_len(result_ref).expect("ciphertext length") {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .expect("read ciphertext byte")
            .expect("ciphertext byte");
        let Value::I64(byte) = value else {
            panic!("ciphertext byte should be an int64, got {value:?}");
        };
        ciphertext.push(byte);
    }

    assert_eq!(
        ciphertext,
        vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
    );

    // The -O3 pipeline (length-aware unrolling + the round-minimizing list
    // scheduler) collapses the ~34k secret multiplies into far fewer
    // communication rounds than the unscheduled build (which needed ~25.7k
    // batch calls). Lock in the round reduction without over-fitting the exact
    // number: it must be well under the -O0 baseline (~6.3k) and the total work
    // and scalar-free invariants must hold.
    let (scalar, batch_calls, batch_items) = engine.counts();
    assert_eq!(scalar, 0, "every secret multiply must be batched at -O3");
    // One proof-driven peel establishes the state shape, then the recurrence-
    // aware unroller keeps the residual rounds rolled. Shape specialization
    // exposes gates with public operands as local work without replicating the
    // full round body: 29,275 products remain interactive.
    assert_eq!(
        batch_items, 29_275,
        "interactive product count must match the optimized circuit"
    );
    assert_eq!(
        planned_triples, batch_items as u64,
        "the preprocessing manifest must exactly cover executed interactive products"
    );
    assert!(
        batch_calls <= 225,
        "scheduler/fixpoint should stay near the 206-round dependency floor; \
         got {batch_calls} rounds"
    );
}

/// Regression for the cross-compile optimizer-budget leak.
///
/// The inline/unroll budgets used to be read from process-global environment
/// variables inside the optimizer. In a process that compiles more than once
/// (e.g. the parallel test runner), a sibling compile that raised those budgets
/// to flatten its program leaked the full-unroll regime into every other
/// compile — pushing this AES-O3 build into the known-buggy full-unroll path,
/// which crashes at runtime with
/// `get_field: array index 0 out of range (length 0)`.
///
/// Budgets are now threaded per-compile via `CompilerOptions`, so this ordering
/// — a heavy full-unroll compile immediately followed by a *default*-budget
/// AES-O3 compile in the same process/thread — must leave AES-O3 in its correct
/// rolled regime and still match the NIST vector.
#[test]
fn repro_aes_o3_double_compile() {
    run_on_large_stack(async move {
        // 1. A sibling compile that opts into the full-unroll regime via
        //    hermetic per-compile budgets (previously: leaking env vars). The
        //    literal-bound loop ensures the raised unroll budget is exercised.
        let sibling_src = "def main() -> int64:\n  var acc = 0\n  for i in 0..64:\n    acc = acc + i\n  return acc\n";
        let sibling_options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: Some(100_000_000),
            unroll_budget: Some(100_000_000),
            unroll_max_expansion: Some(100_000_000),
            ..Default::default()
        };
        stoffellang::compile(sibling_src, "<sibling-full-unroll>", &sibling_options)
            .expect("sibling full-unroll compile");

        // 2. AES at -O3 with DEFAULT budgets, in the same process/thread. If the
        //    sibling's budgets leaked, this would full-unroll and crash; instead
        //    it must reproduce the exact NIST ciphertext (asserted by the impl).
        optimized_aes_at_o3_matches_nist_vector_impl().await;
    });
}

/// Full-optimization path: with the unroll/inline budgets raised so the whole
/// circuit is flattened, the round-minimizing scheduler collapses the ~34k secret
/// multiplies into only a few hundred `batch_mul` communication rounds — a ~60x
/// reduction from the unscheduled ~25.7k. Ignored by default because flattening
/// AES is heavy in a debug build (~60s compile); run explicitly, ideally in
/// release:
///   STOFFEL_UNROLL_BUDGET=100000000 STOFFEL_UNROLL_MAX_EXPANSION=100000000 \
///   STOFFEL_INLINE_BUDGET=100000000 cargo test --release -p stoffel-vm \
///   --test aes_count optimized_aes_full_unroll_minimizes_rounds -- --ignored
#[test]
#[ignore]
fn optimized_aes_full_unroll_minimizes_rounds() {
    run_on_large_stack(async move {
        let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
        // Full-unroll budgets are passed hermetically via CompilerOptions rather
        // than process-global env vars, so this heavy run can't pollute any
        // concurrent compile in the same test process.
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: Some(100_000_000),
            unroll_budget: Some(100_000_000),
            unroll_max_expansion: Some(100_000_000),
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<m>", &options).expect("compile");
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("fns");
        let engine = std::sync::Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for f in functions {
            vm.try_register_function(f).expect("reg");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .expect("exec");
        // Correct ciphertext (NIST AES-128 test vector).
        let Value::Array(result_ref) = result else {
            panic!("AES main should return an array");
        };
        let mut ciphertext = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read")
                .expect("byte");
            let Value::I64(byte) = value else {
                panic!("byte")
            };
            ciphertext.push(byte);
        }
        assert_eq!(
            ciphertext,
            vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
        );
        let (scalar, batch_calls, batch_items) = engine.counts();
        assert_eq!(scalar, 0);
        assert_eq!(batch_items, 29_275);
        assert!(
            batch_calls < 1_000,
            "fully-flattened AES should reach a few hundred multiply rounds; got {batch_calls}"
        );
    });
}

/// Regression for a loop-carried-state mis-optimization when a function with a
/// reassigned (loop-carried) local is inlined more than once. CTR's keystream
/// inlines `aes128_encrypt_rk` (loop-carried `state`) twice — once per block —
/// and at -O3 once produced a wrong block-1 result (C1 != NIST). The single-block
/// AES circuit inlines it only once and was unaffected. This calls a small
/// loop-carried folder twice with distinct inputs and requires -O3 to match -O0.
#[test]
fn loop_carried_state_inlined_twice_o3_matches_o0() {
    run_on_large_stack(loop_carried_state_inlined_twice_o3_matches_o0_impl());
}

async fn loop_carried_state_inlined_twice_o3_matches_o0_impl() {
    let source = r#"
def gate_xor(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

# Loop-carried fold: `result` is reassigned each iteration.
def fold(bits: list[secret bool]) -> secret bool:
  var result: secret bool = Share.from_clear_int(0, 1)
  for i in 0..bits.len():
    result = gate_xor(result, bits[i])
  return result

def main() -> list[int64]:
  # Two INDEPENDENT folds with distinct inputs and distinct results, so a
  # cross-inline collision on `result` is detectable. fold([1,0,0,0]) = 1,
  # fold([0,0,0,0]) = 0.
  var r0 = fold([Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1)])
  var r1 = fold([Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1)])
  var out: list[int64] = []
  var b0: bool = r0.reveal()
  var b1: bool = r1.reveal()
  if b0:
    out.append(1)
  else:
    out.append(0)
  if b1:
    out.append(1)
  else:
    out.append(0)
  return out
"#;

    let run_at = |level: u8| async move {
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<fold>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("fold main should return an array");
        };
        let mut bits = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read bit")
                .expect("bit");
            let Value::I64(b) = value else {
                panic!("bit should be int64, got {value:?}");
            };
            bits.push(b);
        }
        bits
    };

    let expected = vec![1, 0]; // fold([1,0,0,0])=1, fold([0,0,0,0])=0
    let o0 = run_at(0).await;
    let o3 = run_at(3).await;
    assert_eq!(o0, expected, "-O0 fold must be correct");
    assert_eq!(
        o3, expected,
        "-O3 must match -O0 when a loop-carried-state function is inlined twice"
    );
}

/// Differential test for the CTR -O3 full-unroll correctness bug using the
/// reduced counter-increment reproducer. The original AES CTR failure presented
/// as a wrong C1 block; shrinking showed the counter increment itself diverged
/// under -O3 inlining/unrolling/scheduling.
#[test]
fn ctr_full_unroll_c1_matches_o0() {
    run_on_large_stack(ctr_full_unroll_c1_matches_o0_impl());
}

async fn ctr_full_unroll_c1_matches_o0_impl() {
    let base = r#"
def gate_and(a: secret bool, b: secret bool) -> secret bool:
  return a and b

def gate_xor(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

def reveal_byte(byte: list[secret bool]) -> int64:
  var value: int64 = 0
  var b0: bool = byte[0].reveal()
  if b0:
    value += 1
  var b1: bool = byte[1].reveal()
  if b1:
    value += 2
  var b2: bool = byte[2].reveal()
  if b2:
    value += 4
  var b3: bool = byte[3].reveal()
  if b3:
    value += 8
  var b4: bool = byte[4].reveal()
  if b4:
    value += 16
  var b5: bool = byte[5].reveal()
  if b5:
    value += 32
  var b6: bool = byte[6].reveal()
  if b6:
    value += 64
  var b7: bool = byte[7].reveal()
  if b7:
    value += 128
  return value

def reveal_block(block: list[list[secret bool]]) -> list[int64]:
  return [reveal_byte(block[0]), reveal_byte(block[1]), reveal_byte(block[2]), reveal_byte(block[3]), reveal_byte(block[4]), reveal_byte(block[5]), reveal_byte(block[6]), reveal_byte(block[7]), reveal_byte(block[8]), reveal_byte(block[9]), reveal_byte(block[10]), reveal_byte(block[11]), reveal_byte(block[12]), reveal_byte(block[13]), reveal_byte(block[14]), reveal_byte(block[15])]

def public_byte(value: int64) -> list[secret bool]:
  var bits: list[secret bool] = []
  var v: int64 = value
  for i in 0..8:
    bits.append(Share.from_clear_int(v % 2, 1))
    v = v / 2
  return bits

def public_block(values: list[int64]) -> list[list[secret bool]]:
  var block: list[list[secret bool]] = []
  for i in 0..16:
    block.append(public_byte(values[i]))
  return block

def increment_counter_byte(byte: list[secret bool], carry_in: secret bool) -> list[secret bool]:
  var out: list[secret bool] = []
  var carry = carry_in
  for bit_index in 0..8:
    out.append(gate_xor(byte[bit_index], carry))
    carry = gate_and(byte[bit_index], carry)
  return out

def increment_counter_byte_carry(byte: list[secret bool], carry_in: secret bool) -> secret bool:
  var carry = carry_in
  for bit_index in 0..8:
    carry = gate_and(byte[bit_index], carry)
  return carry

def increment_counter_block(counter: list[list[secret bool]]) -> list[list[secret bool]]:
  var out: list[list[secret bool]] = []
  var carry = Share.from_clear_int(1, 1)
  for offset in 0..16:
    var byte_index = 15 - offset
    out.insert(0, increment_counter_byte(counter[byte_index], carry))
    carry = increment_counter_byte_carry(counter[byte_index], carry)
  return out
"#;
    let main_lit = r#"
def main_lit() -> list[int64]:
  var ctr0 = public_block([240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255])
  var ctr1 = increment_counter_block(ctr0)
  return reveal_block(ctr1)
"#;
    let source = format!("{base}\n{main_lit}");

    let run_at = |level: u8, full_unroll: bool, source: String| async move {
        // Full-unroll budgets are threaded hermetically through CompilerOptions
        // (never via process-global env vars), so this test cannot leak a
        // full-unroll regime into any concurrent compile in the same process.
        let budget = if full_unroll { Some(100_000_000) } else { None };
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: budget,
            unroll_budget: budget,
            unroll_max_expansion: budget,
            ..Default::default()
        };
        let compiled = stoffellang::compile(&source, "<ctr-lit>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main_lit", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("main_lit should return an array");
        };
        let mut out = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read byte")
                .expect("byte");
            let Value::I64(b) = value else {
                panic!("byte should be int64, got {value:?}");
            };
            out.push(b);
        }
        out
    };

    let o0 = run_at(0, false, source.clone()).await;
    eprintln!("CTR1_O0 = {:?}", o0);
    // Full-unroll O3 via hermetic per-compile budgets (no env-var leak).
    let o3 = run_at(3, true, source).await;
    eprintln!("CTR1_O3 = {:?}", o3);
    eprintln!("match: {}", o0 == o3);
    assert_eq!(
        o0, o3,
        "ctr1 (counter increment) must match between -O0 and -O3"
    );
}

/// Full-unroll correctness gate for ALL THREE programs (AES circuit, CTR, CBC).
///
/// At large (`100_000_000`) inline/unroll/expansion budgets the whole circuit
/// flattens into one block, which used to trigger the multiply-batcher
/// dependency-model bug: `statement_reads_and_writes` did not model in-place
/// mutators (`append`/`extend`/`insert`) as writes of their receiver, so the
/// scheduler+batcher hoisted a fused `Share.batch_mul` ABOVE the loop that
/// populated its operand lists. At runtime the operands were still empty, the
/// product (and its slices) were empty, and the consumer indexed an empty array
/// — crashing with `get_field: array index 0 out of range (length 0)`.
///
/// With the dep-model fix, all three must run to completion and reveal their
/// NIST-correct output at full unroll. This is the authoritative cryptographic
/// gate for Step 1.
///
/// Ignored by default (flattening all three circuits is heavy: ~18 min in
/// release, longer in debug), matching `optimized_aes_full_unroll_minimizes_rounds`.
/// Run explicitly, ideally in release:
///   cargo test --release -p stoffel-vm --test aes_count \
///     full_unroll_aes_ctr_cbc_match_nist -- --ignored
#[test]
#[ignore = "heavy full-unroll cryptographic gate; run manually with --ignored"]
fn full_unroll_aes_ctr_cbc_match_nist() {
    run_on_large_stack(full_unroll_aes_ctr_cbc_match_nist_impl());
}

async fn full_unroll_aes_ctr_cbc_match_nist_impl() {
    let aes_src = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let ctr_src = include_str!("../../stoffel-lang/examples/mpc_aes128_ctr/main.stfl");
    let cbc_src = include_str!("../../stoffel-lang/examples/mpc_aes128_cbc/main.stfl");

    let plaintext_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_PLAINTEXT_HEX));
    let key_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_KEY_HEX));
    type ClientInputs = Vec<(usize, Vec<stoffel_vm::ClientShare>)>;
    let ctr_cbc_inputs: ClientInputs = vec![(0usize, plaintext_shares), (1usize, key_shares)];

    let programs: Vec<(&str, &str, ClientInputs, &[i64])> = vec![
        ("AES", aes_src, Vec::new(), &AES_NIST_CIPHERTEXT[..]),
        (
            "CTR",
            ctr_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
        (
            "CBC",
            cbc_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
    ];

    for (label, source, inputs, expected) in &programs {
        // Full-unroll budgets threaded hermetically through CompilerOptions.
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            inline_budget: Some(100_000_000),
            unroll_budget: Some(100_000_000),
            unroll_max_expansion: Some(100_000_000),
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<full-unroll-gate>", &options)
            .unwrap_or_else(|e| panic!("{label}: full-unroll compile failed: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");

        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        for (client_id, shares) in inputs {
            vm.store_client_shares(*client_id, shares.clone());
        }

        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("{label}: full-unroll execution failed: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("{label}: main should return an array");
        };
        let mut out = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("result length") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read byte")
                .expect("byte present");
            let Value::I64(byte) = value else {
                panic!("{label}: output byte should be int64, got {value:?}");
            };
            out.push(byte);
        }

        assert_eq!(
            out,
            expected.to_vec(),
            "{label}: full-unroll output must match the NIST vector"
        );
    }
}

// ===========================================================================
// Round-count + correctness gate
// ===========================================================================
//
// Reusable, reproducible gate for round-reducing optimizer work. For each of
// AES-circuit, CTR, and CBC at -O0/-O2/-O3 it COMPILES the live source, runs it
// through the GF(2) `CountingEngine`, and reports BOTH the multiply round count
// (each scalar `multiply_share` or batched `batch_multiply_share` call is one
// communication round) AND whether the revealed output is correct.
//
// Correctness oracle (per program, independent of optimization level):
//   * AES-circuit: the program returns the ciphertext block; it must equal the
//     NIST SP 800-38A AES-128 vector.
//   * CTR / CBC: the program returns the round-tripped second plaintext block
//     (encrypt then decrypt), so it must equal NIST plaintext block P1. This is
//     a true value oracle and ALSO implies -O2/-O3 == -O0 when all three match.
//
// Output: one stable line per (program, level):
//   ROUNDGATE <prog> O<level> mul_rounds=<n> correct=<true|false>
//
// Run with:
//   cargo test -p stoffel-vm --test aes_count round_gate -- --nocapture
//
// The test PRINTS the measurements for every (program, level) and only asserts
// the invariants that are known-stable (see assertions at the end), so it stays
// green as a measurement harness while still surfacing any regression.

/// NIST SP 800-38A AES-128 ciphertext for the single-block circuit example.
const AES_NIST_CIPHERTEXT: [i64; 16] = [
    105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90,
];

/// NIST SP 800-38A AES-128 second plaintext block (P1 = ae2d8a57...8e51). Both
/// CTR and CBC encrypt then decrypt and return this round-tripped block.
const AES_NIST_PLAINTEXT_P1: [i64; 16] = [
    174, 45, 138, 87, 30, 3, 172, 156, 158, 183, 111, 172, 69, 175, 142, 81,
];

/// Two-block NIST plaintext (P0 || P1) and 128-bit key, as the client secret
/// inputs CTR/CBC consume via `ClientStore.take_share_bool`.
const CTR_CBC_PLAINTEXT_HEX: &str =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
const CTR_CBC_KEY_HEX: &str = "2b7e151628aed2a6abf7158809cf4f3c";

/// Decode a hex string to bytes.
fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// Expand bytes into one secret-bool client share per bit, LSB-first within each
/// byte (bit i = 2^i) — the exact ordering `take_client_byte` expects.
fn bits_as_bool_shares(bytes: &[u8]) -> Vec<stoffel_vm::ClientShare> {
    let mut shares = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit in 0..8 {
            let value = (byte >> bit) & 1;
            shares.push(stoffel_vm::ClientShare::typed(
                ShareType::boolean(),
                ShareData::Opaque(vec![value].into()),
            ));
        }
    }
    shares
}

/// Compile `source` at the given optimization level, seed any client inputs,
/// run `main` through the `CountingEngine`, and return
/// `(mul_rounds, revealed_output)`. `mul_rounds` models backend protocol
/// sessions: scalar calls cost one, and oversized batch calls cost one per
/// sequential HoneyBadger capacity chunk.
/// Lever-B / depth measurements for one (program, level) run.
struct LeverMetrics {
    /// Multiply pairs with >=1 public-literal operand (lever B's headroom).
    public_operand_muls: usize,
    /// Subset of the above where BOTH operands are public (fully foldable).
    both_public_muls: usize,
    /// Critical-path multiply depth (theoretical round floor).
    mul_depth: usize,
}

async fn round_gate_run(
    source: &str,
    level: u8,
    client_inputs: &[(usize, Vec<stoffel_vm::ClientShare>)],
) -> Result<(usize, Vec<i64>, LeverMetrics), String> {
    let options = stoffellang::CompilerOptions {
        optimize: level > 0,
        optimization_level: level,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<round-gate>", &options)
        .map_err(|e| format!("compile at -O{level}: {e:?}"))?;
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary
        .try_to_vm_functions()
        .map_err(|e| format!("vm functions at -O{level}: {e:?}"))?;

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .map_err(|e| format!("register function at -O{level}: {e:?}"))?;
    }
    for (client_id, shares) in client_inputs {
        vm.store_client_shares(*client_id, shares.clone());
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .map_err(|e| format!("execute at -O{level}: {e:?}"))?;
    let Value::Array(result_ref) = result else {
        return Err(format!("main should return an array at -O{level}"));
    };
    let mut out = Vec::new();
    let result_len = vm
        .read_array_len(result_ref)
        .map_err(|e| format!("result length at -O{level}: {e:?}"))?;
    for index in 0..result_len {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .map_err(|e| format!("read byte at -O{level}: {e:?}"))?
            .ok_or_else(|| format!("byte {index} missing at -O{level}"))?;
        let Value::I64(byte) = value else {
            return Err(format!(
                "output byte should be int64 at -O{level}, got {value:?}"
            ));
        };
        out.push(byte);
    }

    let (public_operand_muls, both_public_muls, mul_depth) = engine.lever_b_counts();
    Ok((
        engine.protocol_rounds(),
        out,
        LeverMetrics {
            public_operand_muls,
            both_public_muls,
            mul_depth,
        },
    ))
}

// Heavy measurement harness (compiles + runs AES/CTR/CBC at O0/O2/O3): run
// manually as the round-reduction gate with `-- --ignored`. Ignored by default so
// it does not add parallel compile/VM load to the standard test run.
#[ignore = "round-reduction measurement gate; run manually with --ignored"]
#[test]
fn round_gate() {
    run_on_large_stack(round_gate_impl());
}

async fn round_gate_impl() {
    let aes_src = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let ctr_src = include_str!("../../stoffel-lang/examples/mpc_aes128_ctr/main.stfl");
    let cbc_src = include_str!("../../stoffel-lang/examples/mpc_aes128_cbc/main.stfl");

    // CTR/CBC consume 2 plaintext blocks from client slot 0 and the key from
    // client slot 1. With no explicit roster the client store sorts by id, so
    // id 0 -> slot 0 (plaintext) and id 1 -> slot 1 (key).
    let plaintext_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_PLAINTEXT_HEX));
    let key_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_KEY_HEX));
    type ClientInputs = Vec<(usize, Vec<stoffel_vm::ClientShare>)>;
    let ctr_cbc_inputs: ClientInputs = vec![(0usize, plaintext_shares), (1usize, key_shares)];

    // (program label, source, no-input or client-input, expected output)
    let programs: Vec<(&str, &str, ClientInputs, &[i64])> = vec![
        ("AES", aes_src, Vec::new(), &AES_NIST_CIPHERTEXT[..]),
        (
            "CTR",
            ctr_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
        (
            "CBC",
            cbc_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
    ];

    // Collected so the measurement harness is also a correctness gate.
    let mut all_correct = true;
    let mut measured_rounds: std::collections::HashMap<(&str, u8), usize> =
        std::collections::HashMap::new();

    for (label, source, inputs, expected) in &programs {
        for level in [0u8, 2, 3] {
            match round_gate_run(source, level, inputs).await {
                Ok((mul_rounds, output, lever)) => {
                    measured_rounds.insert((*label, level), mul_rounds);
                    let correct = output == *expected;
                    // The stable, machine-parseable gate line.
                    println!(
                        "ROUNDGATE {label} O{level} mul_rounds={mul_rounds} correct={correct}"
                    );
                    // Lever-B headroom: multiplies whose `ab` term has a public-literal
                    // operand (could become a local `mul_scalar`). `both_public` is the
                    // fully-constant-foldable subset.
                    println!(
                        "PUBMUL {label} O{level} public_operand_muls={} both_public={}",
                        lever.public_operand_muls, lever.both_public_muls
                    );
                    // Critical-path multiply depth = theoretical round floor.
                    println!("MULDEPTH {label} O{level} mul_depth={}", lever.mul_depth);
                    if !correct {
                        eprintln!(
                            "ROUNDGATE {label} O{level} MISMATCH: got {output:?}, expected {expected:?}"
                        );
                    }
                    if !correct {
                        all_correct = false;
                    }
                }
                Err(error) => {
                    println!("ROUNDGATE {label} O{level} mul_rounds=ERR correct=false");
                    eprintln!("ROUNDGATE {label} O{level} ERROR: {error}");
                    all_correct = false;
                }
            }
        }
    }

    assert!(
        all_correct,
        "AES, CTR, and CBC must match their NIST outputs at every optimization level"
    );
    for label in ["CTR", "CBC"] {
        assert!(
            measured_rounds[&(label, 3)] < measured_rounds[&(label, 2)]
                && measured_rounds[&(label, 2)] < measured_rounds[&(label, 0)],
            "{label} must reduce online rounds monotonically from O0 to O2 to O3"
        );
    }
}

// ===========================================================================
// Per-dependency-depth round histogram (measurement only)
// ===========================================================================
//
// For each program at -O3 this compiles + runs the live source through the
// CountingEngine, then breaks the multiply ROUNDS down by critical-path output
// depth. Each backend protocol session is one round (`call_id`); an oversized
// VM batch call contributes multiple sequential call ids. For every output
// depth d it reports:
//   pairs   = number of multiply pairs whose output depth is d
//   layer_cap = ceil(pairs/256), a diagnostic packing count for that output
//               depth (NOT a lower bound because one batch may mix depths)
//   actual  = number of rounds whose pairs are (max-)at depth d
//   delta   = actual - layer_cap (fragmentation diagnostic only)
//   pub     = pairs at depth d with a public operand (lever 4 headroom)
// The sound global lower bound is max(critical-path depth, ceil(total pairs/256)).
// Unlike the former sum-of-depth-ceilings metric, this can never exceed a legal
// schedule merely because a batch mixes output depths. The difference between
// actual rounds and this bound is a certified *possible* improvement envelope,
// not proof that every round in the envelope is achievable under precedence.
// Opens are counted separately as full online sessions. They are not yet nodes
// in the multiplication DAG (clear values cannot carry the opaque producer
// frontier), so the certified lower/upper bounds below remain multiply-only and
// `observed_online_sessions` is deliberately reported without claiming a full
// interactive-DAG optimum.
//
// Run with:
//   cargo test --release -p stoffel-vm --test aes_count round_histogram \
//     -- --ignored --nocapture

async fn histogram_run(
    source: &str,
    level: u8,
    client_inputs: &[(usize, Vec<stoffel_vm::ClientShare>)],
) -> Result<
    (
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        Vec<i64>,
        Vec<PairRecord>,
        Vec<(String, usize)>,
    ),
    String,
> {
    let inline_budget = std::env::var("STOFFEL_HIST_INLINE_BUDGET")
        .ok()
        .and_then(|value| value.parse().ok());
    let unroll_budget = std::env::var("STOFFEL_HIST_UNROLL_BUDGET")
        .ok()
        .and_then(|value| value.parse().ok());
    let unroll_max_expansion = std::env::var("STOFFEL_HIST_UNROLL_MAX_EXPANSION")
        .ok()
        .and_then(|value| value.parse().ok());
    let options = stoffellang::CompilerOptions {
        optimize: level > 0,
        optimization_level: level,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        inline_budget,
        unroll_budget,
        unroll_max_expansion,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<histogram>", &options)
        .map_err(|e| format!("compile at -O{level}: {e:?}"))?;
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary
        .try_to_vm_functions()
        .map_err(|e| format!("vm functions at -O{level}: {e:?}"))?;
    let static_batch_call_sites = functions
        .iter()
        .flat_map(|function| function.instructions())
        .filter(|instruction| {
            matches!(instruction, Instruction::CALL(name) if name == "Share.batch_mul")
        })
        .count();
    let static_instructions = functions
        .iter()
        .map(|function| function.instructions().len())
        .sum();
    let main_static_batch_call_sites = functions
        .iter()
        .find(|function| function.name() == "main")
        .map(|function| {
            function
                .instructions()
                .iter()
                .filter(|instruction| {
                    matches!(instruction, Instruction::CALL(name) if name == "Share.batch_mul")
                })
                .count()
        })
        .unwrap_or(0);
    let main_static_instructions = functions
        .iter()
        .find(|function| function.name() == "main")
        .map(|function| function.instructions().len())
        .unwrap_or(0);

    let engine = Arc::new(CountingEngine::default());
    let executed_call_sites = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    if std::env::var("STOFFEL_HIST_CALLSITES").is_ok_and(|value| value != "0") {
        let call_sites = executed_call_sites.clone();
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(Instruction::CALL(name))
                        if name == "Share.batch_mul"
                )
            },
            move |_, context| {
                call_sites.lock().expect("call-site trace lock").push((
                    context
                        .current_instruction_function_name()
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    context.current_instruction_index(),
                ));
                Ok(())
            },
            0,
        );
    }
    for function in functions {
        vm.try_register_function(function)
            .map_err(|e| format!("register function at -O{level}: {e:?}"))?;
    }
    for (client_id, shares) in client_inputs {
        vm.store_client_shares(*client_id, shares.clone());
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .map_err(|e| format!("execute at -O{level}: {e:?}"))?;
    let Value::Array(result_ref) = result else {
        return Err(format!("main should return an array at -O{level}"));
    };
    let mut out = Vec::new();
    let result_len = vm
        .read_array_len(result_ref)
        .map_err(|e| format!("result length at -O{level}: {e:?}"))?;
    for index in 0..result_len {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .map_err(|e| format!("read byte at -O{level}: {e:?}"))?
            .ok_or_else(|| format!("byte {index} missing at -O{level}"))?;
        let Value::I64(byte) = value else {
            return Err(format!(
                "output byte should be int64 at -O{level}, got {value:?}"
            ));
        };
        out.push(byte);
    }
    let (scalar_opens, batch_opens) = engine.open_protocol_breakdown();
    let (scalar_muls, batch_calls, _batch_items) = engine.counts();
    debug_assert_eq!(
        scalar_muls, 0,
        "O3 histogram should contain no scalar multiplies"
    );
    let executed_call_sites = executed_call_sites
        .lock()
        .expect("call-site trace lock")
        .clone();
    Ok((
        engine.protocol_rounds(),
        batch_calls,
        static_batch_call_sites,
        static_instructions,
        main_static_batch_call_sites,
        main_static_instructions,
        engine.open_protocol_rounds(),
        scalar_opens,
        batch_opens,
        out,
        engine.pair_log_snapshot(),
        executed_call_sites,
    ))
}

fn print_depth_histogram(
    label: &str,
    rounds: usize,
    source_batch_calls: usize,
    static_batch_call_sites: usize,
    static_instructions: usize,
    main_static_batch_call_sites: usize,
    main_static_instructions: usize,
    open_rounds: usize,
    scalar_opens: usize,
    batch_opens: usize,
    correct: bool,
    log: &[PairRecord],
    executed_call_sites: &[(String, usize)],
) {
    use std::collections::BTreeMap;
    let dag_critical_path = validate_pair_dag(log);
    // Per output depth: total pairs, pairs with a public operand.
    let mut pairs_at: BTreeMap<u32, usize> = BTreeMap::new();
    let mut pub_at: BTreeMap<u32, usize> = BTreeMap::new();
    // Per round (call_id): (min depth, max depth, pair count).
    let mut calls: BTreeMap<u32, (u32, u32, usize)> = BTreeMap::new();
    let mut total_pub = 0usize;
    let mut total_both = 0usize;
    for r in log {
        *pairs_at.entry(r.depth).or_default() += 1;
        if r.pub_operand {
            *pub_at.entry(r.depth).or_default() += 1;
            total_pub += 1;
        }
        if r.both_public {
            total_both += 1;
        }
        let e = calls.entry(r.call_id).or_insert((u32::MAX, 0, 0));
        e.0 = e.0.min(r.depth);
        e.1 = e.1.max(r.depth);
        e.2 += 1;
    }
    // Attribute each round to its max output depth; count singletons / mixed.
    let mut actual_at: BTreeMap<u32, usize> = BTreeMap::new();
    let mut singleton_rounds = 0usize;
    let mut mixed_rounds = 0usize;
    for (mn, mx, n) in calls.values() {
        *actual_at.entry(*mx).or_default() += 1;
        if *n == 1 {
            singleton_rounds += 1;
        }
        if mn != mx {
            mixed_rounds += 1;
        }
    }
    let depths: Vec<u32> = pairs_at.keys().copied().collect();
    println!(
        "HIST {label} O3 rounds={rounds} correct={correct} pairs={} max_depth={} pub_pairs={} both_public={}",
        log.len(),
        depths.last().copied().unwrap_or(0),
        total_pub,
        total_both,
    );
    println!("HIST {label} depth | pairs | layer_cap | actual | delta | pub");
    for d in &depths {
        let pairs = pairs_at[d];
        let layer_cap = pairs.div_ceil(256);
        let actual = actual_at.get(d).copied().unwrap_or(0);
        let pub_pairs = pub_at.get(d).copied().unwrap_or(0);
        let delta = actual as i64 - layer_cap as i64;
        println!(
            "HIST {label}  {d:>4} | {pairs:>5} | {layer_cap:>9} | {actual:>6} | {delta:>5} | {pub_pairs:>5}"
        );
    }
    let critical_path = depths.last().copied().unwrap_or(0) as usize;
    assert_eq!(
        critical_path, dag_critical_path,
        "histogram and explicit DAG critical paths must agree"
    );
    let work_bound = log.len().div_ceil(MODELED_MPC_BATCH_CAPACITY);
    let sound_lower_bound = critical_path.max(work_bound);
    let dag_schedule = dag_list_schedule(log, MODELED_MPC_BATCH_CAPACITY);
    let dag_list_upper = dag_schedule.len();
    let (window_lower_bound, window_witness) =
        window_capacity_lower_bound(log, MODELED_MPC_BATCH_CAPACITY, dag_list_upper.min(rounds));
    let (resource_window_lower_bound, resource_window_witness) =
        resource_window_capacity_lower_bound(
            log,
            MODELED_MPC_BATCH_CAPACITY,
            dag_list_upper.min(rounds),
        );
    let pivot_witness = critical_chain_pivot_lower_bound(log, MODELED_MPC_BATCH_CAPACITY);
    let certified_lower_bound = sound_lower_bound
        .max(window_lower_bound)
        .max(resource_window_lower_bound)
        .max(pivot_witness.lower_bound);
    let call_schedule = call_dag_list_schedule(log, MODELED_MPC_BATCH_CAPACITY);
    let call_list_upper = call_schedule.len();
    let utilized = log.len() as f64 / (rounds.max(1) * MODELED_MPC_BATCH_CAPACITY) as f64 * 100.0;
    let (source_segments, max_segments_per_round) = scheduled_source_segments(log, &dag_schedule);
    let clustered_schedule = dag_source_clustered_schedule(log, MODELED_MPC_BATCH_CAPACITY);
    let (clustered_segments, clustered_max_segments) =
        scheduled_source_segments(log, &clustered_schedule);
    assert!(
        rounds >= sound_lower_bound,
        "observed schedule cannot beat its critical-path/work lower bound"
    );
    assert!(
        dag_list_upper >= sound_lower_bound,
        "a legal DAG schedule cannot beat the sound lower bound"
    );
    assert!(
        rounds >= certified_lower_bound && dag_list_upper >= certified_lower_bound,
        "legal schedules cannot beat a certified precedence/capacity lower bound"
    );
    assert!(
        calls
            .values()
            .all(|(_, _, work)| *work <= MODELED_MPC_BATCH_CAPACITY),
        "the observed schedule must respect backend multiply capacity"
    );
    println!(
        "HIST {label} TOTALS actual_rounds={rounds} sound_lb={sound_lower_bound} \
window_lb={window_lower_bound} pivot_lb={} certified_lb={certified_lower_bound} certified_gap={} \
resource_window_lb={resource_window_lower_bound} \
basic_gap={} dag_list_upper={dag_list_upper} dag_sched_gap={} \
critical_path={critical_path} work_bound={work_bound} \
distinct_depths={} singleton_rounds={singleton_rounds} mixed_depth_rounds={mixed_rounds} \
open_rounds={open_rounds} scalar_opens={scalar_opens} batch_opens={batch_opens} \
observed_online_sessions={}",
        pivot_witness.lower_bound,
        rounds.saturating_sub(certified_lower_bound),
        rounds - sound_lower_bound,
        rounds.saturating_sub(dag_list_upper),
        depths.len(),
        rounds + open_rounds,
    );
    println!(
        "HIST {label} PIVOT node={} ancestors={} descendants={} lower_bound={}",
        pivot_witness.pivot,
        pivot_witness.ancestors,
        pivot_witness.descendants,
        pivot_witness.lower_bound,
    );
    if let Some(witness) = window_witness {
        println!(
            "HIST {label} WINDOW horizon={} interval={}-{} forced_work={} \
interval_capacity={} overload={}",
            witness.horizon,
            witness.first_round,
            witness.last_round,
            witness.forced_work,
            witness.interval_capacity,
            witness.forced_work - witness.interval_capacity,
        );
    }
    if let Some(witness) = resource_window_witness {
        println!(
            "HIST {label} RESOURCE_WINDOW horizon={} interval={}-{} forced_work={} \
interval_capacity={} overload={}",
            witness.horizon,
            witness.first_round,
            witness.last_round,
            witness.forced_work,
            witness.interval_capacity,
            witness.forced_work - witness.interval_capacity,
        );
    }
    println!(
        "HIST {label} ENCODING source_segments={source_segments} \
max_segments_per_round={max_segments_per_round} avg_segments_per_round={:.2} \
clustered_rounds={} clustered_segments={clustered_segments} \
clustered_max_segments={clustered_max_segments}",
        source_segments as f64 / dag_list_upper.max(1) as f64,
        clustered_schedule.len(),
    );
    println!(
        "HIST {label} CHUNKS actual={rounds} source_batch_calls={source_batch_calls} \
static_batch_call_sites={static_batch_call_sites} \
static_instructions={static_instructions} \
main_batch_call_sites={main_static_batch_call_sites} main_instructions={main_static_instructions} \
call_dag_upper={call_list_upper} \
call_repack_gain={} lane_split_gain={} utilization={utilized:.1}%",
        rounds.saturating_sub(call_list_upper),
        call_list_upper.saturating_sub(dag_list_upper),
    );
    if !executed_call_sites.is_empty() {
        assert_eq!(
            executed_call_sites.len(),
            calls.len(),
            "one traced source site per executed protocol call"
        );
        for (call_id, (function, instruction)) in executed_call_sites.iter().enumerate() {
            let (min_depth, max_depth, work) = calls[&(call_id as u32)];
            println!(
                "HIST {label} CALL id={call_id} site={function}:{instruction} work={work} depth={min_depth}-{max_depth}"
            );
        }
        for (round, packed) in call_schedule.iter().enumerate() {
            if packed.len() > 1 {
                println!("HIST {label} CALLPACK round={round} calls={packed:?}");
            }
        }
    }
    println!();
}

/// Persist the measured multiplication DAG in a compact, versioned binary
/// format when `STOFFEL_AES_COUNT_DAG_OUT` is set. This keeps expensive
/// compiler/VM execution separate from exact-scheduler experiments. The path
/// may contain `{label}`, which is replaced with the lower-case program label.
fn maybe_write_pair_dag(label: &str, log: &[PairRecord]) -> std::io::Result<()> {
    use std::io::Write;

    let Ok(path) = std::env::var("STOFFEL_AES_COUNT_DAG_OUT") else {
        return Ok(());
    };
    let path = path.replace("{label}", &label.to_ascii_lowercase());
    let mut writer = std::io::BufWriter::new(std::fs::File::create(path)?);
    writer.write_all(b"STFDAG01")?;
    writer.write_all(&(MODELED_MPC_BATCH_CAPACITY as u32).to_le_bytes())?;
    writer.write_all(&(log.len() as u32).to_le_bytes())?;
    for record in log {
        writer.write_all(&record.pair_id.to_le_bytes())?;
        writer.write_all(&record.call_id.to_le_bytes())?;
        writer.write_all(&record.depth.to_le_bytes())?;
        writer.write_all(&(record.parents.len() as u32).to_le_bytes())?;
        for &parent in &record.parents {
            writer.write_all(&parent.to_le_bytes())?;
        }
    }
    writer.flush()
}

fn read_pair_dag(path: &std::path::Path) -> std::io::Result<(usize, Vec<PairRecord>)> {
    use std::io::Read;

    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != b"STFDAG01" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unrecognized Stoffel pair-DAG format",
        ));
    }
    let read_u32 = |reader: &mut std::io::BufReader<std::fs::File>| {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok::<_, std::io::Error>(u32::from_le_bytes(bytes))
    };
    let capacity = read_u32(&mut reader)? as usize;
    let count = read_u32(&mut reader)? as usize;
    let mut log = Vec::with_capacity(count);
    for expected_id in 0..count {
        let pair_id = read_u32(&mut reader)?;
        let call_id = read_u32(&mut reader)?;
        let depth = read_u32(&mut reader)?;
        let parent_count = read_u32(&mut reader)? as usize;
        if pair_id as usize != expected_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pair-DAG ids are not dense and ordered",
            ));
        }
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            parents.push(read_u32(&mut reader)?);
        }
        log.push(PairRecord {
            pair_id,
            parents,
            call_id,
            depth,
            pub_operand: false,
            both_public: false,
        });
    }
    Ok((capacity, log))
}

#[ignore = "cached multiplication-DAG scheduler analysis; set STOFFEL_PAIR_DAG_IN"]
#[test]
fn cached_pair_dag_scheduler_analysis() {
    let Some(path) = std::env::var_os("STOFFEL_PAIR_DAG_IN") else {
        eprintln!(
            "skipping cached pair-DAG analysis: set STOFFEL_PAIR_DAG_IN to a cache written by round_histogram"
        );
        return;
    };
    let (capacity, log) = read_pair_dag(std::path::Path::new(&path)).expect("read pair DAG");
    let critical_path = validate_pair_dag(&log);
    let component_sizes = weak_component_sizes(&log);
    let work_bound = log.len().div_ceil(capacity);
    let forward = dag_list_schedule(&log, capacity);
    let backward = dag_backward_list_schedule(&log, capacity);
    let backward_deadline = dag_backward_deadline_schedule(&log, capacity);
    let critical_fan_in_backward = dag_backward_priority_list_schedule(
        &log,
        capacity,
        BackwardPriority::CriticalPredecessorFanIn,
    );
    let critical_fan_in_forward =
        dag_forward_from_backward_schedule(&log, capacity, &critical_fan_in_backward);
    let chain_partition = critical_chain_partition_lower_bound(&log, capacity);
    let pivot = critical_chain_pivot_lower_bound(&log, capacity);
    let legal_upper_bound = critical_fan_in_forward.len();
    let (window_lower_bound, window_witness) =
        window_capacity_lower_bound(&log, capacity, legal_upper_bound);
    let (resource_window_lower_bound, resource_window_witness) =
        resource_window_capacity_lower_bound(&log, capacity, legal_upper_bound);
    let priorities = vec![
        DagListPriority::BottomSourceAscending,
        DagListPriority::BottomHighFanout,
        DagListPriority::BottomSuccessorPressure,
    ];
    let priority_schedules: Vec<_> = priorities
        .into_iter()
        .map(|priority| {
            let (schedule, ready_counts) = dag_priority_list_schedule(&log, capacity, priority);
            (format!("{priority:?}"), schedule, ready_counts)
        })
        .collect();
    let priority_rounds: Vec<_> = priority_schedules
        .iter()
        .map(|(priority, schedule, _)| (priority, schedule.len()))
        .collect();
    let underfilled: Vec<_> = forward
        .iter()
        .enumerate()
        .filter(|(_, round)| round.len() < capacity)
        .map(|(round_index, round)| {
            let calls: std::collections::BTreeSet<_> =
                round.iter().map(|&node| log[node].call_id).collect();
            (round_index, round.len(), calls)
        })
        .collect();
    println!(
        "CACHED_DAG nodes={} edges={} capacity={} critical_path={} work_bound={} \
chain_partition_bound={} chain_partition_pivots={} \
single_pivot_bound={} single_pivot_node={} \
window_bound={} window_witness={:?} resource_window_bound={} resource_window_witness={:?} \
forward_rounds={} backward_rounds={} backward_deadline_rounds={} \
critical_fan_in_backward_rounds={} critical_fan_in_forward_rounds={} priorities={priority_rounds:?}",
        log.len(),
        log.iter().map(|record| record.parents.len()).sum::<usize>(),
        capacity,
        critical_path,
        work_bound,
        chain_partition.lower_bound,
        chain_partition.pivots.len(),
        pivot.lower_bound,
        pivot.pivot,
        window_lower_bound,
        window_witness,
        resource_window_lower_bound,
        resource_window_witness,
        forward.len(),
        backward.len(),
        backward_deadline.len(),
        critical_fan_in_backward.len(),
        critical_fan_in_forward.len(),
    );
    println!("CACHED_DAG component_sizes={component_sizes:?}");
    println!("CACHED_DAG underfilled={underfilled:?}");
    let (_, source_ascending, ready_counts) = &priority_schedules[0];
    let constrained: Vec<_> = source_ascending
        .iter()
        .enumerate()
        .filter(|(round, jobs)| jobs.len() < capacity || ready_counts[*round] > capacity)
        .map(|(round, jobs)| (round, jobs.len(), ready_counts[round]))
        .collect();
    println!("CACHED_DAG frontier={constrained:?}");
}

#[ignore = "per-depth round histogram measurement; run manually with --ignored --nocapture"]
#[test]
fn round_histogram() {
    run_on_large_stack(round_histogram_impl());
}

async fn round_histogram_impl() {
    let aes_src = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let ctr_src = include_str!("../../stoffel-lang/examples/mpc_aes128_ctr/main.stfl");
    let cbc_src = include_str!("../../stoffel-lang/examples/mpc_aes128_cbc/main.stfl");

    let plaintext_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_PLAINTEXT_HEX));
    let key_shares = bits_as_bool_shares(&hex_bytes(CTR_CBC_KEY_HEX));
    type ClientInputs = Vec<(usize, Vec<stoffel_vm::ClientShare>)>;
    let ctr_cbc_inputs: ClientInputs = vec![(0usize, plaintext_shares), (1usize, key_shares)];

    let programs: Vec<(&str, &str, ClientInputs, &[i64])> = vec![
        ("AES", aes_src, Vec::new(), &AES_NIST_CIPHERTEXT[..]),
        (
            "CTR",
            ctr_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
        (
            "CBC",
            cbc_src,
            ctr_cbc_inputs.clone(),
            &AES_NIST_PLAINTEXT_P1[..],
        ),
    ];

    let label_filter = std::env::var("STOFFEL_AES_COUNT_FILTER").ok();

    for (label, source, inputs, expected) in &programs {
        if label_filter
            .as_deref()
            .is_some_and(|filter| !label.eq_ignore_ascii_case(filter))
        {
            continue;
        }
        match histogram_run(source, 3, inputs).await {
            Ok((
                rounds,
                source_batch_calls,
                static_batch_call_sites,
                static_instructions,
                main_static_batch_call_sites,
                main_static_instructions,
                open_rounds,
                scalar_opens,
                batch_opens,
                output,
                log,
                executed_call_sites,
            )) => {
                let correct = output == *expected;
                maybe_write_pair_dag(label, &log)
                    .unwrap_or_else(|error| panic!("write {label} DAG: {error}"));
                print_depth_histogram(
                    label,
                    rounds,
                    source_batch_calls,
                    static_batch_call_sites,
                    static_instructions,
                    main_static_batch_call_sites,
                    main_static_instructions,
                    open_rounds,
                    scalar_opens,
                    batch_opens,
                    correct,
                    &log,
                    &executed_call_sites,
                );
                assert!(correct, "{label} O3 must match its NIST output");
            }
            Err(error) => {
                panic!("HIST {label} O3 failed: {error}");
            }
        }
    }
}

/// Regression test for the opt-level >= 1 spill-slot reload cache: a value that
/// is reassigned inside a runtime loop while spilled (a multi-def spill slot
/// carried across the back edge) is exactly where a stale cached reload would
/// produce wrong values while straight-line code still passes. The program
/// keeps ~26 loop-invariant, data-dependent values live across a 128-iteration
/// `while` loop (forcing clear-bank spills) and accumulates through a spilled
/// loop-carried variable; every optimization level must agree with -O0.
#[test]
fn loop_carried_spill_slot_reloads_are_correct() {
    run_on_large_stack(loop_carried_spill_slot_reloads_are_correct_impl());
}

async fn loop_carried_spill_slot_reloads_are_correct_impl() {
    // Build the source: a first runtime loop makes `seed` opaque to constant
    // folding, a chain of 24 live-to-the-end variables plus 8 loop-carried
    // accumulators forces clear-bank spilling, and the second loop reassigns
    // the (spilled) accumulators on every iteration.
    let mut source = String::from(
        "def main() -> int64:\n\
         \x20 var n = 128\n\
         \x20 var i = 0\n\
         \x20 var seed = 0\n\
         \x20 while i < n:\n\
         \x20   seed = seed + i\n\
         \x20   i = i + 1\n\
         \x20 var a0 = seed + 1\n",
    );
    for k in 1..24 {
        source.push_str(&format!("  var a{k} = a{} + seed\n", k - 1));
    }
    for k in 0..8 {
        source.push_str(&format!("  var t{k} = seed + a{}\n", k * 3));
    }
    source.push_str("  var j = 0\n  while j < n:\n");
    for k in 0..8 {
        source.push_str(&format!("    t{k} = t{k} + a{}\n", 23 - k));
    }
    source.push_str("    j = j + 1\n  var sum = 0\n");
    for k in 0..24 {
        source.push_str(&format!("  sum = sum + a{k}\n"));
    }
    for k in 0..8 {
        source.push_str(&format!("  sum = sum + t{k}\n"));
    }
    source.push_str("  return sum\n");

    let run_at = |level: u8| {
        let source = source.clone();
        async move {
            let options = stoffellang::CompilerOptions {
                optimize: level > 0,
                optimization_level: level,
                mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
                ..Default::default()
            };
            let compiled = stoffellang::compile(&source, "<loop-carried-spill>", &options)
                .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
            // The test is only meaningful if the accumulator actually spills:
            // require a multi-def spill slot (>= 2 static STS to one slot — the
            // loop-carried reassignments of `t`).
            if level > 0 {
                let mut sts_per_slot: std::collections::HashMap<usize, usize> =
                    std::collections::HashMap::new();
                for inst in &compiled.main_chunk.instructions {
                    if let stoffel_vm_types::instructions::Instruction::STS(slot, _) = inst {
                        *sts_per_slot.entry(*slot).or_default() += 1;
                    }
                }
                assert!(
                    !sts_per_slot.is_empty(),
                    "-O{level}: expected register pressure to spill (no STS emitted; \
                     raise the live-variable count in this test)"
                );
                assert!(
                    sts_per_slot.values().any(|&count| count >= 2),
                    "-O{level}: expected a multi-def (loop-carried) spill slot, got {sts_per_slot:?}"
                );
            }
            let binary = stoffellang::convert_to_binary(&compiled);
            let functions = binary.try_to_vm_functions().expect("vm functions");
            let engine = Arc::new(CountingEngine::default());
            let mut vm = VirtualMachine::builder()
                .with_mpc_engine(engine.clone())
                .build();
            for function in functions {
                vm.try_register_function(function)
                    .expect("register function");
            }
            vm.execute_async("main", engine.as_ref())
                .await
                .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"))
        }
    };

    let baseline = run_at(0).await;
    for level in 1..=3 {
        let result = run_at(level).await;
        assert_eq!(
            result, baseline,
            "-O{level} disagrees with -O0 on the loop-carried spilled accumulator"
        );
    }
}

/// Regression test for the CTR-only -O3 SROA empty-husk crash.
///
/// SROA (`scalarize_local_arrays`) deletes the `append` builder calls of a
/// scalar-backed local list, emitting a length-0 array and substituting each
/// constant-index read with the captured element. The bug: when a scalar-backed
/// list's handle is *aliased* under a new name (`var counter = initial_counter`)
/// or *captured* into another list, the empty-husk handle escaped into a sibling
/// block (an inlined callee body scalarized in its own per-block pass) where it
/// was read as a real, length-0 array — faulting at runtime with
/// `get_field: array index 0 out of range (length 0)`. The name-keyed demotion
/// machinery never saw the cross-block read. The fix demotes a scalar-backed
/// source whenever its bare handle can escape via such an alias/capture
/// (fail-closed: the real array is rebuilt), leaving the MPC round structure
/// untouched.
///
/// This self-contained program exercises exactly that shape: CTR keystream with
/// a loop-carried `counter` alias, `list.insert(0, ...)`-built blocks, and
/// nested flatten/regroup lists — then encrypts and decrypts, so `main` must
/// round-trip back to the plaintext `[16..=31]` at every optimization level.
/// Before the fix it crashed at -O3 while -O0/-O2 were correct.
const CTR_SROA_HUSK_SRC: &str = include_str!("data/ctr_sroa_husk.stfl");

#[test]
fn ctr_sroa_husk_o3_matches_o0() {
    run_on_large_stack(ctr_sroa_husk_o3_matches_o0_impl());
}

async fn ctr_sroa_husk_o3_matches_o0_impl() {
    let inputs: Vec<(usize, Vec<stoffel_vm::ClientShare>)> = Vec::new();
    let expected: Vec<i64> = (16..=31).collect();
    for level in [0u8, 2u8, 3u8] {
        let out = round_gate_run(CTR_SROA_HUSK_SRC, level, &inputs)
            .await
            .unwrap_or_else(|e| panic!("CTR SROA husk repro failed at -O{level}: {e}"));
        assert_eq!(
            out.1, expected,
            "-O{level} CTR keystream round-trip diverged (SROA empty-husk regression)"
        );
    }
}
