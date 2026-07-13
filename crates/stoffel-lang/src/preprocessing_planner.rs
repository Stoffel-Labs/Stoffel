//! Interprocedural preprocessing-demand analysis.
//!
//! StoffelLang programs consume MPC preprocessing material (Beaver triples,
//! random bits/ints) as they execute. The runtime needs an accurate up-front
//! estimate so it can pre-generate exactly that much material. A naive
//! intraprocedural count massively undercounts: it cannot see that a helper
//! containing one secret multiplication is called inside `for i in 0..10`
//! (×10), nor that `Share.batch_mul(a, b)` consumes `len(a)` triples when `a`'s
//! length is determined by a caller.
//!
//! This module performs a small abstract interpretation over the AST, threading
//! two abstract domains through a pure (side-effect-free) evaluator:
//!
//! * [`Len`] — the statically known length of a list-typed value (for sizing
//!   `batch_mul`, folding `.len()`, and counting list-iteration loops).
//! * [`Secrecy`] — whether a value is secret, clear, or unknown (to recognise
//!   the secret×secret operations that actually consume a triple).
//!
//! The result is a [`PreprocessingDemand`] (reused verbatim from
//! `stoffel-vm-types`) describing the total material one program run consumes.
//! When a path cannot be sized statically (recursion, runtime-sized batches,
//! data-dependent loops) the analysis sets `dynamic = true` rather than silently
//! undercounting.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::ast::{AstNode, Parameter, Value};
use crate::errors::SourceLocation;
use crate::symbol_table::SymbolType;
use stoffel_vm_types::compiled_binary::{MpcBackend, PreprocessingDemand};
use stoffel_vm_types::core_types::{
    DEFAULT_FIXED_POINT_FRACTIONAL_BITS, DEFAULT_FIXED_POINT_TOTAL_BITS,
};

fn preprocessing_diagnostic(message: std::fmt::Arguments<'_>) {
    if std::env::var_os("STOFFEL_PREPROCESSING_DIAGNOSTICS").is_some() {
        eprintln!("preprocessing planner: {message}");
    }
}

/// Statically known list shape of a value: its length and, recursively, the
/// shape of its elements (so nested lists like `list[list[secret bool]]` can be
/// sized — e.g. an AES state of 16 bytes, each 8 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Len {
    /// A list of exactly `len` elements, each having element shape `elem`.
    Known { len: usize, elem: Box<Len> },
    /// Not a list, or a length only known at runtime.
    Unknown,
}

impl Len {
    /// A list of `len` elements whose own shapes are unknown (a flat list).
    fn flat(len: usize) -> Len {
        Len::Known {
            len,
            elem: Box::new(Len::Unknown),
        }
    }

    /// The outer element count, if statically known.
    fn count(&self) -> Option<usize> {
        match self {
            Len::Known { len, .. } => Some(*len),
            Len::Unknown => None,
        }
    }

    /// The shape of this list's elements (`Unknown` if not a known list).
    fn element(&self) -> Len {
        match self {
            Len::Known { elem, .. } => (**elem).clone(),
            Len::Unknown => Len::Unknown,
        }
    }
}

/// Whether a value (or, for lists, its elements) is secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Secrecy {
    Secret,
    Clear,
    Unknown,
}

impl Secrecy {
    /// Result secrecy of an arithmetic combination of two operands: secret if
    /// either side is secret, clear if both are clear, otherwise unknown.
    fn join_arith(self, other: Secrecy) -> Secrecy {
        match (self, other) {
            (Secrecy::Secret, _) | (_, Secrecy::Secret) => Secrecy::Secret,
            (Secrecy::Clear, Secrecy::Clear) => Secrecy::Clear,
            _ => Secrecy::Unknown,
        }
    }

    /// Merge secrecy across two control-flow branches that may both reach a use.
    fn merge_branch(self, other: Secrecy) -> Secrecy {
        if self == other {
            self
        } else {
            Secrecy::Unknown
        }
    }
}

impl std::hash::Hash for Secrecy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (*self as u8).hash(state);
    }
}

static NEXT_EXACT_ELEMENTS_ID: AtomicU64 = AtomicU64::new(1);

/// Exact aggregate contents shared by abstract values.
///
/// `id` identifies one immutable logical snapshot. Cloning the `Arc` preserves
/// the snapshot identity, while every mutation rotates the id first. Call-cache
/// keys can therefore distinguish changed lane provenance in O(1) without
/// recursively rebuilding a key for every element on every call.
#[derive(Debug, Clone)]
struct ExactElements {
    id: u64,
    values: Vec<AbstractValue>,
}

impl ExactElements {
    fn shared(values: Vec<AbstractValue>) -> Arc<Self> {
        Arc::new(Self {
            id: Self::next_id(),
            values,
        })
    }

    fn values_mut(elements: &mut Arc<Self>) -> &mut Vec<AbstractValue> {
        let elements = Arc::make_mut(elements);
        elements.id = Self::next_id();
        &mut elements.values
    }

    fn next_id() -> u64 {
        let id = NEXT_EXACT_ELEMENTS_ID.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, u64::MAX, "exhausted exact aggregate snapshot ids");
        id
    }
}

impl std::ops::Deref for ExactElements {
    type Target = [AbstractValue];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

/// The abstract value an expression evaluates to: its list shape, its secrecy,
/// and — for clear integers — its constant value (used for loop bounds).
#[derive(Debug, Clone)]
struct AbstractValue {
    len: Len,
    secrecy: Secrecy,
    /// The value is known to all parties while still inhabiting a secret-share
    /// type (for example the result of `Share.from_clear_int`). Such values can
    /// participate in integer/boolean multiplication without a Beaver triple.
    public_share: bool,
    /// Statically known clear integer value, if any.
    int: Option<u64>,
    /// Fractional bits of a secret fixed-point value, for `/` truncation cost.
    frac_bits: Option<usize>,
    /// Integer share width when known (one bit identifies the boolean domain).
    bit_length: Option<usize>,
    /// Exact integral value of a public share. Kept separate from `int`, which
    /// denotes an ordinary clear integer usable as a loop bound/index.
    public_integer: Option<i64>,
    /// Exact elements of a statically materialized list. This preserves
    /// per-lane public-share provenance for mixed `batch_mul` operands instead
    /// of collapsing the whole aggregate to one all-public bit.
    elements: Option<Arc<ExactElements>>,
}

impl AbstractValue {
    fn unknown() -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Unknown,
            public_share: false,
            int: None,
            frac_bits: None,
            bit_length: None,
            public_integer: None,
            elements: None,
        }
    }

    fn clear_int(value: u64) -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Clear,
            public_share: false,
            int: Some(value),
            frac_bits: None,
            bit_length: None,
            public_integer: None,
            elements: None,
        }
    }

    fn clear() -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Clear,
            public_share: false,
            int: None,
            frac_bits: None,
            bit_length: None,
            public_integer: None,
            elements: None,
        }
    }

    fn secret() -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Secret,
            public_share: false,
            int: None,
            frac_bits: None,
            bit_length: None,
            public_integer: None,
            elements: None,
        }
    }

    fn public_share(frac_bits: Option<usize>) -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Secret,
            public_share: true,
            int: None,
            frac_bits,
            bit_length: None,
            public_integer: None,
            elements: None,
        }
    }

    fn secret_with_bit_length(bit_length: Option<usize>) -> Self {
        let mut value = Self::secret();
        value.bit_length = bit_length;
        value
    }

    fn public_integral_share(bit_length: Option<usize>, value: i64) -> Option<Self> {
        if bit_length == Some(1) && !matches!(value, 0 | 1) {
            return None;
        }
        let mut result = Self::public_share(None);
        result.bit_length = bit_length;
        result.public_integer = Some(value);
        Some(result)
    }
}

/// Per-scope binding of variable names to their abstract values.
type Env = HashMap<String, AbstractValue>;

/// Result of analysing a function body: the demand it incurs and the abstract
/// value it returns.
#[derive(Debug, Clone)]
struct CallResult {
    demand: PreprocessingDemand,
    ret: AbstractValue,
}

/// Hashable form of [`Len`], used in memo / call-shape keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LenKey {
    Known { len: usize, elem: Box<LenKey> },
    Unknown,
}

impl From<&Len> for LenKey {
    fn from(len: &Len) -> Self {
        match len {
            Len::Known { len, elem } => LenKey::Known {
                len: *len,
                elem: Box::new(LenKey::from(elem.as_ref())),
            },
            Len::Unknown => LenKey::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AbstractValueKey {
    len: LenKey,
    secrecy: Secrecy,
    public_share: bool,
    int: Option<u64>,
    frac_bits: Option<usize>,
    bit_length: Option<usize>,
    public_integer: Option<i64>,
    elements_id: Option<u64>,
}

impl From<&AbstractValue> for AbstractValueKey {
    fn from(value: &AbstractValue) -> Self {
        Self {
            len: LenKey::from(&value.len),
            secrecy: value.secrecy,
            public_share: value.public_share,
            int: value.int,
            frac_bits: value.frac_bits,
            bit_length: value.bit_length,
            public_integer: value.public_integer,
            elements_id: value.elements.as_ref().map(|elements| elements.id),
        }
    }
}

/// A memoisation / call-stack key: the function plus the complete abstract
/// values of its arguments. Lane provenance and clear constants affect demand,
/// so omitting either can reuse an estimate from an inequivalent call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallKey {
    name: String,
    arguments: Vec<AbstractValueKey>,
}

/// A user-defined function the planner can analyse.
struct FunctionInfo<'a> {
    parameters: &'a [Parameter],
    body: &'a AstNode,
}

/// The interprocedural planner. Holds the program's user functions plus a memo
/// table keyed on call shape.
struct Planner<'a> {
    functions: HashMap<String, &'a FunctionInfo<'a>>,
    memo: HashMap<CallKey, CallResult>,
    mpc_backend: MpcBackend,
    work: PlannerWork,
    loop_profiles: HashMap<SourceLocation, LoopProfile>,
}

#[derive(Debug, Clone, Copy, Default)]
struct LoopProfile {
    invocations: u64,
    iterations: u64,
    expression_visits: u64,
}

/// Deterministic units of planner work used by scaling regression tests. These
/// counters describe algorithmic work rather than machine-dependent elapsed
/// time, so they are stable enough to gate CI.
#[derive(Debug, Clone, Copy, Default)]
struct PlannerWork {
    expression_visits: u64,
    exact_loop_iterations: u64,
    summarized_loop_iterations: u64,
    uniform_append_summaries: u64,
    aggregate_mutations: u64,
    aggregate_lanes_appended: u64,
    aggregate_lanes_copied: u64,
    call_keys_built: u64,
}

/// Compute the total preprocessing demand of `program` (the top-level AST, a
/// `Block` of definitions). Returns the element-wise maximum over every
/// top-level function's demand, so whichever entry the runtime selects is
/// covered.
pub fn plan_preprocessing_demand(program: &AstNode) -> PreprocessingDemand {
    plan_preprocessing_demand_for_backend(program, MpcBackend::default())
}

/// Compute preprocessing demand using the material pools consumed by
/// `mpc_backend`. Random integer generation is backed by PRandInt under
/// HoneyBadger, while AVSS currently implements it using ordinary random field
/// shares.
pub fn plan_preprocessing_demand_for_backend(
    program: &AstNode,
    mpc_backend: MpcBackend,
) -> PreprocessingDemand {
    // The analysis recurses through the program's call graph, which for large
    // straight-line circuits (e.g. the AES S-box and its callers) can nest many
    // frames deep. Run it on a dedicated thread with a generous stack so the
    // recursion never overflows the (smaller) default/main stack. `std::thread::
    // scope` lets the worker borrow `program` without `'static`.
    const ANALYSIS_STACK_SIZE: usize = 256 * 1024 * 1024;
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("preprocessing-demand-analysis".to_string())
            .stack_size(ANALYSIS_STACK_SIZE)
            .spawn_scoped(scope, || {
                plan_preprocessing_demand_inner(program, mpc_backend)
            })
            .expect("failed to spawn preprocessing-demand analysis thread")
            .join()
            .expect("preprocessing-demand analysis thread panicked")
    })
}

fn plan_preprocessing_demand_inner(
    program: &AstNode,
    mpc_backend: MpcBackend,
) -> PreprocessingDemand {
    plan_preprocessing_demand_inner_with_work(program, mpc_backend).0
}

fn plan_preprocessing_demand_inner_with_work(
    program: &AstNode,
    mpc_backend: MpcBackend,
) -> (PreprocessingDemand, PlannerWork) {
    let mut infos: Vec<(String, FunctionInfo)> = Vec::new();
    collect_functions(program, &mut infos);

    let functions: HashMap<String, &FunctionInfo> = infos
        .iter()
        .map(|(name, info)| (name.clone(), info))
        .collect();

    let mut planner = Planner {
        functions,
        memo: HashMap::new(),
        mpc_backend,
        work: PlannerWork::default(),
        loop_profiles: HashMap::new(),
    };

    // Program entries are the functions the runtime can actually invoke as a
    // top-level entry point: the conventional entry `main` (which may take
    // client-supplied arguments, whose lengths are unknown but whose secrecy
    // follows their type), plus any zero-parameter function (another possible
    // entry). An *arbitrary* parameter-taking helper is NOT an entry — the
    // runtime cannot supply its (often secret-list) arguments — so analysing it
    // speculatively with unknown-length args would only pollute the estimate
    // with spurious `dynamic` flags. Helpers are instead analysed precisely via
    // the concrete calls their entry makes. If nothing qualifies, fall back to
    // analysing every function so we never emit an empty estimate.
    let entries: Vec<&(String, FunctionInfo)> = {
        let selected: Vec<&(String, FunctionInfo)> = infos
            .iter()
            .filter(|(name, info)| name == "main" || info.parameters.is_empty())
            .collect();
        if selected.is_empty() {
            infos.iter().collect()
        } else {
            selected
        }
    };

    let mut total = PreprocessingDemand::default();
    for (name, info) in entries {
        let result = planner.analyze_entry(name, info);
        total = max_demand(total, result.demand);
    }
    if std::env::var("STOFFEL_OPT_TIMING").is_ok_and(|value| value != "0" && !value.is_empty()) {
        eprintln!(
            "[planner-work] expressions={} loop_iterations={} summarized_loop_iterations={} uniform_append_summaries={} aggregate_mutations={} lanes_appended={} lanes_copied={} call_keys={}",
            planner.work.expression_visits,
            planner.work.exact_loop_iterations,
            planner.work.summarized_loop_iterations,
            planner.work.uniform_append_summaries,
            planner.work.aggregate_mutations,
            planner.work.aggregate_lanes_appended,
            planner.work.aggregate_lanes_copied,
            planner.work.call_keys_built,
        );
        let mut loops: Vec<_> = planner.loop_profiles.iter().collect();
        loops.sort_unstable_by_key(|(_, profile)| std::cmp::Reverse(profile.expression_visits));
        for (location, profile) in loops.into_iter().take(12) {
            eprintln!(
                "[planner-loop] location={location} invocations={} iterations={} expressions={}",
                profile.invocations, profile.iterations, profile.expression_visits,
            );
        }
    }
    (total, planner.work)
}

/// Walk `node` collecting every top-level function definition (recursing into
/// the outer `Block`, but not into function bodies).
fn collect_functions<'a>(node: &'a AstNode, out: &mut Vec<(String, FunctionInfo<'a>)>) {
    match node {
        AstNode::Block(statements) => {
            for statement in statements {
                collect_functions(statement, out);
            }
        }
        AstNode::FunctionDefinition {
            name: Some(name),
            parameters,
            body,
            pragmas,
            ..
        } => {
            // Builtins have no analysable StoffelLang body.
            let is_builtin = pragmas.iter().any(|pragma| match pragma {
                crate::ast::Pragma::Simple(n, _) | crate::ast::Pragma::KeyValue(n, _, _) => {
                    n == "builtin"
                }
            });
            if !is_builtin {
                out.push((
                    name.clone(),
                    FunctionInfo {
                        parameters: parameters.as_slice(),
                        body,
                    },
                ));
            }
        }
        _ => {}
    }
}

/// Element-wise maximum of two demands (`dynamic` is OR'd).
fn max_demand(a: PreprocessingDemand, b: PreprocessingDemand) -> PreprocessingDemand {
    PreprocessingDemand {
        triples: a.triples.max(b.triples),
        randoms: a.randoms.max(b.randoms),
        prandbits: a.prandbits.max(b.prandbits),
        prandints: a.prandints.max(b.prandints),
        prandint_bits: a.prandint_bits.max(b.prandint_bits),
        dynamic: a.dynamic || b.dynamic,
    }
}

impl<'a> Planner<'a> {
    /// Analyse a top-level function as a program entry. Its parameters' lengths
    /// are unknown (a caller would supply them) but their secrecy follows their
    /// type annotation.
    fn analyze_entry(&mut self, name: &str, info: &FunctionInfo<'a>) -> CallResult {
        let arguments: Vec<AbstractValue> = info
            .parameters
            .iter()
            .map(|parameter| AbstractValue {
                len: Len::Unknown,
                secrecy: param_element_secrecy(parameter),
                public_share: false,
                int: None,
                frac_bits: param_frac_bits(parameter),
                bit_length: None,
                public_integer: None,
                elements: None,
            })
            .collect();
        let mut call_stack = Vec::new();
        self.analyze_call(name, info, &arguments, &mut call_stack)
    }

    /// Analyse one call of `name` with the given argument shapes, memoised on
    /// `(name, arg_lens, arg_secrecy)`. Recursion (the same name already on the
    /// call stack) yields a `dynamic` floor.
    fn analyze_call(
        &mut self,
        name: &str,
        info: &FunctionInfo<'a>,
        arguments: &[AbstractValue],
        call_stack: &mut Vec<String>,
    ) -> CallResult {
        self.work.call_keys_built = self.work.call_keys_built.saturating_add(1);
        let key = CallKey {
            name: name.to_string(),
            arguments: arguments.iter().map(AbstractValueKey::from).collect(),
        };
        if let Some(cached) = self.memo.get(&key) {
            return cached.clone();
        }

        // Recursion: we cannot bound the depth statically, so flag dynamic.
        if call_stack.iter().any(|frame| frame == name) {
            preprocessing_diagnostic(format_args!(
                "dynamic recursion: {} -> {name}",
                call_stack.join(" -> ")
            ));
            return CallResult {
                demand: PreprocessingDemand {
                    dynamic: true,
                    ..Default::default()
                },
                ret: AbstractValue::unknown(),
            };
        }

        // Seed the parameter environment from the call-site argument shapes and
        // the parameters' declared element secrecy.
        let mut env = Env::new();
        for (index, param) in info.parameters.iter().enumerate() {
            let mut value = arguments
                .get(index)
                .cloned()
                .unwrap_or_else(AbstractValue::unknown);
            value.frac_bits = param_frac_bits(param).or(value.frac_bits);
            env.insert(param.name.clone(), value);
        }

        call_stack.push(name.to_string());
        let mut demand = PreprocessingDemand::default();
        let mut ret: Option<AbstractValue> = None;
        self.eval_block_like(info.body, &mut env, &mut demand, &mut ret, call_stack);
        call_stack.pop();

        let result = CallResult {
            demand,
            ret: ret.unwrap_or_else(AbstractValue::unknown),
        };
        self.memo.insert(key, result.clone());
        result
    }

    /// Evaluate a statement or block for its side effects on `env`, `demand`,
    /// and (via `Return`) the function's `ret` value.
    fn eval_block_like(
        &mut self,
        node: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        match node {
            AstNode::Block(statements) => {
                for statement in statements {
                    self.eval_block_like(statement, env, demand, ret, call_stack);
                }
            }
            AstNode::VariableDeclaration {
                name,
                value,
                type_annotation,
                is_secret,
                ..
            } => {
                let mut value = match value {
                    Some(value) => self.eval_expr(value, env, demand, call_stack),
                    None => AbstractValue::unknown(),
                };
                // A declared `secret` / `list[secret ...]` type pins the element
                // secrecy even when the initialiser is an empty (or otherwise
                // secrecy-ambiguous) list literal that will be filled in later.
                let declared_secret = *is_secret
                    || type_annotation
                        .as_deref()
                        .is_some_and(annotation_contains_secret);
                if declared_secret {
                    value.secrecy = Secrecy::Secret;
                }
                env.insert(name.clone(), value);
            }
            AstNode::Assignment { target, value, .. } => {
                let value = self.eval_expr(value, env, demand, call_stack);
                if let AstNode::Identifier(name, _) = target.as_ref() {
                    env.insert(name.clone(), value);
                } else {
                    // Index/field assignment: evaluate the target for any
                    // embedded calls. It also mutates the aggregate rooted at a
                    // simple name: once a non-public share is stored anywhere
                    // in a list/object, the aggregate is no longer provably an
                    // all-public operand for a later batch multiplication.
                    self.eval_expr(target, env, demand, call_stack);
                    let updated_exact_lane = update_exact_aggregate_assignment(env, target, &value);
                    if !updated_exact_lane {
                        if let Some(root) = assignment_root(target) {
                            if let Some(aggregate) = env.get_mut(root) {
                                aggregate.secrecy = aggregate.secrecy.join_arith(value.secrecy);
                                aggregate.public_share &= value.public_share;
                                aggregate.elements = None;
                            }
                        }
                    }
                }
            }
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                location,
            } => self.eval_for_loop(
                variables, iterable, body, location, env, demand, ret, call_stack,
            ),
            AstNode::WhileLoop {
                condition, body, ..
            } => self.eval_while_loop(condition, body, env, demand, ret, call_stack),
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                self.eval_expr(condition, env, demand, call_stack);
                self.eval_if_statement(then_branch, else_branch, env, demand, ret, call_stack);
            }
            AstNode::Return { value, .. } => {
                if let Some(value) = value {
                    let value = self.eval_expr(value, env, demand, call_stack);
                    merge_into_ret(ret, Some(value));
                }
            }
            AstNode::DiscardStatement { expression, .. } => {
                self.eval_expr(expression, env, demand, call_stack);
            }
            // Any expression used in statement position (e.g. a bare call).
            other => {
                self.eval_expr(other, env, demand, call_stack);
            }
        }
    }

    /// Evaluate an `if` in statement position, taking the branch-wise maximum of
    /// demand (the runtime must provision for whichever branch executes).
    fn eval_if_statement(
        &mut self,
        then_branch: &AstNode,
        else_branch: &Option<Box<AstNode>>,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        let mut then_env = env.clone();
        let mut then_demand = PreprocessingDemand::default();
        let mut then_ret = ret.clone();
        self.eval_block_like(
            then_branch,
            &mut then_env,
            &mut then_demand,
            &mut then_ret,
            call_stack,
        );

        let (else_demand, else_ret, else_env) = match else_branch {
            Some(else_branch) => {
                let mut else_env = env.clone();
                let mut else_demand = PreprocessingDemand::default();
                let mut else_ret = ret.clone();
                self.eval_block_like(
                    else_branch,
                    &mut else_env,
                    &mut else_demand,
                    &mut else_ret,
                    call_stack,
                );
                (else_demand, else_ret, else_env)
            }
            None => (PreprocessingDemand::default(), ret.clone(), env.clone()),
        };

        // Demand of a conditional is the per-element maximum of its branches.
        add_demand(demand, &max_demand(then_demand, else_demand));

        // The function return value may come from either branch.
        *ret = merge_opt_ret(then_ret, else_ret);

        // Preserve facts only when both branches agree. In particular, a value
        // that is public before the conditional must not remain classified as
        // public if either branch replaces it with a secret share.
        for name in env.keys().cloned().collect::<Vec<_>>() {
            let Some(then_value) = then_env.get(&name).cloned() else {
                continue;
            };
            let Some(else_value) = else_env.get(&name).cloned() else {
                continue;
            };
            env.insert(name, merge_value(then_value, else_value));
        }
    }

    /// Evaluate a `while` loop. The counted shape codegen emits everywhere —
    /// `v = <known>; while v OP <known>: … ; v = v ± step` (or `v = v * k`) —
    /// gets its trip count inferred and is then treated exactly like a counted
    /// `for` loop (body analysed once, demand scaled, list growth applied
    /// `count` times), so `while`-built programs provision correctly instead of
    /// reporting ZERO demand. Anything non-canonical falls back to
    /// analyse-once + `dynamic`, and — crucially — poisons the lengths of every
    /// list the body grew (`apply_loop_length_growth_unknown`): before this,
    /// the discarded body env left the PRE-loop lengths visible, so a
    /// post-loop `batch_mul` over a `while`-filled list counted len 0 triples
    /// with `dynamic: false` (the all-zero manifests that starved the runtime).
    #[allow(clippy::too_many_arguments)]
    fn eval_while_loop(
        &mut self,
        condition: &AstNode,
        body: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        self.eval_expr(condition, env, demand, call_stack);
        let count = self.while_trip_count(condition, body, env, demand, call_stack);

        let mut body_env = env.clone();
        if let Some((var, _, _)) = while_condition_parts(condition) {
            // The counter's per-iteration value varies; never fold its start.
            body_env.insert(var.to_string(), AbstractValue::clear());
        }
        let mut body_demand = PreprocessingDemand::default();
        let mut body_ret = ret.clone();
        self.eval_block_like(
            body,
            &mut body_env,
            &mut body_demand,
            &mut body_ret,
            call_stack,
        );
        merge_into_ret(ret, body_ret);

        match count {
            Some(count) => {
                add_demand(demand, &scale_demand(&body_demand, count));
                apply_loop_length_growth(env, &body_env, count);
                // The counter's post-loop value is loop-shape-dependent; keep it
                // conservative (clear, value unknown) rather than stale-at-start.
                if let Some((var, _, _)) = while_condition_parts(condition) {
                    env.insert(var.to_string(), AbstractValue::clear());
                }
            }
            None => {
                add_demand(demand, &body_demand);
                if has_any_material(&body_demand) {
                    preprocessing_diagnostic(format_args!(
                        "dynamic while loop in {} at {:?}: body demand {:?}",
                        call_stack.join(" -> "),
                        condition.location(),
                        body_demand
                    ));
                    demand.dynamic = true;
                }
                apply_loop_length_growth_unknown(env, &body_env);
                if let Some((var, _, _)) = while_condition_parts(condition) {
                    env.insert(var.to_string(), AbstractValue::clear());
                }
            }
        }
    }

    /// Infer the trip count of the canonical counted `while` shape, or `None`.
    /// Requirements: condition `v < | <= | > | >= <bound>` with `v` a tracked
    /// int and `<bound>` foldable; EXACTLY one assignment to `v` anywhere in
    /// the body, at the body's top level, of shape `v = v + s`, `v = v - s`
    /// (`s` a positive literal, direction matching the comparison) or
    /// `v = v * k` (`k >= 2`, ascending).
    fn while_trip_count(
        &mut self,
        condition: &AstNode,
        body: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> Option<u64> {
        let (var, cmp, bound_expr) = while_condition_parts(condition)?;
        let start = env.get(var)?.int?;
        let _ = &demand;
        let bound = {
            let mut scratch = PreprocessingDemand::default();
            self.eval_expr(bound_expr, env, &mut scratch, call_stack)
                .int?
        };
        let step = while_step(body, var)?;

        match (cmp, step) {
            ("<", WhileStep::Add(s)) if bound > start => Some((bound - start).div_ceil(s)),
            ("<", WhileStep::Add(_)) => Some(0),
            ("<=", WhileStep::Add(s)) if bound >= start => Some((bound - start) / s + 1),
            ("<=", WhileStep::Add(_)) => Some(0),
            (">", WhileStep::Sub(s)) if start > bound => Some((start - bound).div_ceil(s)),
            (">", WhileStep::Sub(_)) => Some(0),
            (">=", WhileStep::Sub(s)) if start >= bound => Some((start - bound) / s + 1),
            (">=", WhileStep::Sub(_)) => Some(0),
            ("<", WhileStep::Mul(k)) if start >= 1 && k >= 2 => {
                let mut v = start;
                let mut c = 0u64;
                while v < bound && c < 64 {
                    v = v.saturating_mul(k);
                    c += 1;
                }
                (c < 64).then_some(c)
            }
            _ => None,
        }
    }

    /// Evaluate a `for` loop: count its iterations when statically known,
    /// multiply the body demand by that count, and bind the loop variable.
    #[allow(clippy::too_many_arguments)]
    fn eval_for_loop(
        &mut self,
        variables: &[String],
        iterable: &AstNode,
        body: &AstNode,
        location: &SourceLocation,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        const EXACT_LOOP_INTERPRETATION_LIMIT: u64 = 10_000;

        // Determine iteration count and the loop variable's abstract value.
        let (count, loop_var_value, range_start, exact_loop_elements): (
            Option<u64>,
            AbstractValue,
            Option<u64>,
            Option<Arc<ExactElements>>,
        ) = match iterable {
            AstNode::BinaryOperation {
                op, left, right, ..
            } if op == ".." => {
                // Evaluate bounds for any embedded calls, then fold.
                let start = self.eval_expr(left, env, demand, call_stack);
                let end = self.eval_expr(right, env, demand, call_stack);
                let count = match (start.int, end.int) {
                    (Some(a), Some(b)) if b >= a => Some(b - a),
                    _ => None,
                };
                // Exact counted loops are interpreted iteration by iteration,
                // so preserve the initial induction value when it is known.
                (count, AbstractValue::clear(), start.int, None)
            }
            _ => {
                // `for x in <list>`: the count is the list length; bind `x` to
                // the collection's element shape and secrecy.
                let collection = self.eval_expr(iterable, env, demand, call_stack);
                let count = collection.len.count().map(|n| n as u64);
                let element = AbstractValue {
                    len: collection.len.element(),
                    secrecy: collection.secrecy,
                    public_share: collection.public_share,
                    int: None,
                    frac_bits: None,
                    bit_length: collection.bit_length,
                    public_integer: None,
                    elements: None,
                };
                (count, element, None, collection.elements)
            }
        };

        // Scaling a body analysed only in its first-iteration environment is
        // unsound for loop-carried MPC state: a public accumulator can make the
        // first product local, then become secret so every later product needs
        // a triple. Interpret ordinary statically-bounded loops exactly so each
        // iteration observes the preceding iteration's abstract state. The cap
        // protects compiler latency for pathological literal bounds; those keep
        // the conservative dynamic fallback below instead of claiming an exact
        // (potentially under-provisioned) manifest.
        if let Some(count) = count.filter(|count| *count <= EXACT_LOOP_INTERPRETATION_LIMIT) {
            let expressions_before = self.work.expression_visits;
            if self.try_summarize_uniform_append_loop(
                variables,
                body,
                count,
                range_start,
                env,
                demand,
                call_stack,
            ) {
                let profile = self.loop_profiles.entry(location.clone()).or_default();
                profile.invocations = profile.invocations.saturating_add(1);
                profile.iterations = profile.iterations.saturating_add(count);
                profile.expression_visits = profile.expression_visits.saturating_add(
                    self.work
                        .expression_visits
                        .saturating_sub(expressions_before),
                );
                return;
            }
            let visible_names: HashSet<String> = env.keys().cloned().collect();
            let mut body_local_names = Vec::new();
            collect_declared_names(body, &mut body_local_names);
            body_local_names.sort_unstable();
            body_local_names.dedup();
            for iteration in 0..count {
                self.work.exact_loop_iterations = self.work.exact_loop_iterations.saturating_add(1);
                if let Some(first) = variables.first() {
                    let value = range_start
                        .and_then(|start| start.checked_add(iteration))
                        .map(AbstractValue::clear_int)
                        .or_else(|| {
                            exact_loop_elements
                                .as_ref()
                                .and_then(|elements| elements.get(iteration as usize))
                                .cloned()
                        })
                        .unwrap_or_else(|| loop_var_value.clone());
                    env.insert(first.clone(), value);
                }
                for extra in variables.iter().skip(1) {
                    env.insert(extra.clone(), AbstractValue::unknown());
                }

                let mut iteration_demand = PreprocessingDemand::default();
                let mut iteration_ret = None;
                self.eval_block_like(
                    body,
                    env,
                    &mut iteration_demand,
                    &mut iteration_ret,
                    call_stack,
                );
                add_demand(demand, &iteration_demand);
                merge_into_ret(ret, iteration_ret);

                // Body-local declarations and newly introduced loop variables
                // do not escape an iteration. Remove only names that the AST
                // can introduce instead of cloning/scanning the entire env.
                for name in body_local_names.iter().chain(variables) {
                    if !visible_names.contains(name) {
                        env.remove(name);
                    }
                }
            }
            let profile = self.loop_profiles.entry(location.clone()).or_default();
            profile.invocations = profile.invocations.saturating_add(1);
            profile.iterations = profile.iterations.saturating_add(count);
            profile.expression_visits = profile.expression_visits.saturating_add(
                self.work
                    .expression_visits
                    .saturating_sub(expressions_before),
            );
            return;
        }

        // Bind the loop variable(s) before analysing the body. (Only single-var
        // loops are supported by codegen; bind the first, leave the rest
        // unknown.)
        let mut body_env = env.clone();
        if let Some(first) = variables.first() {
            body_env.insert(first.clone(), loop_var_value);
        }
        for extra in variables.iter().skip(1) {
            body_env.insert(extra.clone(), AbstractValue::unknown());
        }

        let mut body_demand = PreprocessingDemand::default();
        let mut body_ret = ret.clone();
        self.eval_block_like(
            body,
            &mut body_env,
            &mut body_demand,
            &mut body_ret,
            call_stack,
        );
        // A `return` reached inside the loop body contributes to the function's
        // return value.
        merge_into_ret(ret, body_ret);

        match count {
            Some(count) => {
                add_demand(demand, &scale_demand(&body_demand, count));
                // Reaching this arm means the known bound exceeded the exact
                // interpretation budget above. The scaled first-iteration
                // demand is only a floor for possible loop-carried state.
                demand.dynamic = true;
                // Apply the per-iteration list-length growth `count` times. A
                // list appended to once per iteration ends at `start + count`.
                // (This composes across nested loops: the inner loop writes its
                // scaled growth into the outer loop's body env, which the outer
                // loop then scales again.)
                apply_loop_length_growth(env, &body_env, count);
            }
            None => {
                // Unknown iteration count: provision one iteration and flag the
                // estimate dynamic so the runtime keeps headroom. Any list grown
                // by an unbounded loop now has an unknown length.
                add_demand(demand, &body_demand);
                if has_any_material(&body_demand) {
                    preprocessing_diagnostic(format_args!(
                        "dynamic for loop in {} at {:?}: body demand {:?}",
                        call_stack.join(" -> "),
                        iterable.location(),
                        body_demand
                    ));
                    demand.dynamic = true;
                }
                apply_loop_length_growth_unknown(env, &body_env);
            }
        }
    }

    /// Summarize a uniform append-only map loop in closed form.
    ///
    /// The accepted shape is one `append(out, value)` statement over an exact
    /// integer range. `value` may use the induction variable only to index exact
    /// aggregates whose selected lanes all have the same abstract value. That
    /// is a proof that every iteration has identical preprocessing demand and
    /// appends identical abstract provenance. Evaluating the value once, scaling
    /// its demand, and growing the exact aggregate by `count` therefore produces
    /// the same manifest and post-loop environment as scalar interpretation.
    #[allow(clippy::too_many_arguments)]
    fn try_summarize_uniform_append_loop(
        &mut self,
        variables: &[String],
        body: &AstNode,
        count: u64,
        range_start: Option<u64>,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> bool {
        let [loop_var] = variables else {
            return false;
        };
        let Some(start) = range_start else {
            return false;
        };
        let Some((receiver, value)) = single_append_loop_body(body) else {
            return false;
        };
        let AstNode::Identifier(receiver_name, _) = receiver else {
            return false;
        };
        if node_references_identifier(value, receiver_name)
            || !expression_is_uniform_over_range(value, loop_var, start, count, env)
        {
            return false;
        }
        let Ok(count_usize) = usize::try_from(count) else {
            return false;
        };
        if count == 0 {
            self.work.uniform_append_summaries =
                self.work.uniform_append_summaries.saturating_add(1);
            return true;
        }

        let previous_loop_var = env.insert(loop_var.clone(), AbstractValue::clear_int(start));
        let mut iteration_demand = PreprocessingDemand::default();
        let element = self.eval_expr(value, env, &mut iteration_demand, call_stack);
        // Keep the compact summary on scalar lanes. Repeating a nested exact
        // aggregate would expand a large tree that branch merging must later
        // rebuild recursively; those loops retain ordinary exact interpretation
        // until the abstract domain has an explicit run-length representation.
        if element.elements.is_some() || element.len.count().is_some() {
            if let Some(previous) = previous_loop_var {
                env.insert(loop_var.clone(), previous);
            } else {
                env.remove(loop_var);
            }
            return false;
        }
        add_demand(demand, &scale_demand(&iteration_demand, count));

        self.list_grow(
            Some(receiver),
            count_usize,
            Some(element.secrecy),
            Some(element.public_share),
            Some(element.len.clone()),
            Some(ExactElements::shared(vec![element; count_usize])),
            env,
        );

        if let Some(previous) = previous_loop_var {
            let last = start.saturating_add(count.saturating_sub(1));
            let mut final_value = AbstractValue::clear_int(last);
            // Preserve the existing binding's declared abstract category when
            // its concrete induction value is not otherwise observable.
            final_value.secrecy = previous.secrecy;
            env.insert(loop_var.clone(), final_value);
        } else {
            env.remove(loop_var);
        }
        self.work.summarized_loop_iterations =
            self.work.summarized_loop_iterations.saturating_add(count);
        self.work.uniform_append_summaries = self.work.uniform_append_summaries.saturating_add(1);
        true
    }

    /// Evaluate an expression for its abstract value, accumulating any demand it
    /// incurs into `demand`.
    fn eval_expr(
        &mut self,
        node: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> AbstractValue {
        self.work.expression_visits = self.work.expression_visits.saturating_add(1);
        match node {
            AstNode::Literal { value, .. } => match value {
                Value::Int { value, .. } => u64::try_from(*value)
                    .map(AbstractValue::clear_int)
                    .unwrap_or_else(|_| AbstractValue::clear()),
                _ => AbstractValue::clear(),
            },
            AstNode::Identifier(name, _) => env
                .get(name)
                .cloned()
                .unwrap_or_else(AbstractValue::unknown),
            AstNode::ListLiteral { elements, .. } => {
                let mut secrecy = Secrecy::Clear;
                let mut public_share = !elements.is_empty();
                let mut element_shape: Option<Len> = None;
                let mut exact_elements = Vec::with_capacity(elements.len());
                for element in elements {
                    let value = self.eval_expr(element, env, demand, call_stack);
                    public_share &= value.public_share;
                    if value.secrecy == Secrecy::Secret {
                        secrecy = Secrecy::Secret;
                    } else if value.secrecy == Secrecy::Unknown && secrecy != Secrecy::Secret {
                        secrecy = Secrecy::Unknown;
                    }
                    // Track the elements' shared shape so nested lists are sized.
                    element_shape = Some(match element_shape {
                        Some(existing) if existing == value.len => existing,
                        Some(_) => Len::Unknown,
                        None => value.len.clone(),
                    });
                    exact_elements.push(value);
                }
                AbstractValue {
                    len: Len::Known {
                        len: elements.len(),
                        elem: Box::new(element_shape.unwrap_or(Len::Unknown)),
                    },
                    secrecy,
                    public_share,
                    int: None,
                    frac_bits: None,
                    bit_length: None,
                    public_integer: None,
                    elements: Some(ExactElements::shared(exact_elements)),
                }
            }
            AstNode::BinaryOperation {
                op, left, right, ..
            } => self.eval_binary_operation(op, left, right, env, demand, call_stack),
            AstNode::UnaryOperation { operand, .. } => {
                // `not` and other unary ops are free; propagate operand secrecy.
                let value = self.eval_expr(operand, env, demand, call_stack);
                let public_integer = value
                    .public_integer
                    .and_then(|value| (value == 0 || value == 1).then_some(1 - value));
                AbstractValue {
                    len: Len::Unknown,
                    secrecy: value.secrecy,
                    public_share: value.public_share,
                    int: None,
                    frac_bits: value.frac_bits,
                    bit_length: value.bit_length,
                    public_integer,
                    elements: None,
                }
            }
            AstNode::FunctionCall {
                function,
                arguments,
                resolved_return_type,
                ..
            } => self.eval_function_call(
                function,
                arguments,
                resolved_return_type.as_ref(),
                env,
                demand,
                call_stack,
            ),
            AstNode::IndexAccess { base, index, .. } => {
                let base = self.eval_expr(base, env, demand, call_stack);
                let index = self.eval_expr(index, env, demand, call_stack);
                if let Some(value) = index
                    .int
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| base.elements.as_ref()?.get(index))
                {
                    return value.clone();
                }
                // An element of a list inherits the list's element shape and
                // secrecy (so `state[i]` on a list of 8-bit bytes is a byte of
                // length 8).
                AbstractValue {
                    len: base.len.element(),
                    secrecy: base.secrecy,
                    public_share: base.public_share,
                    int: None,
                    frac_bits: None,
                    bit_length: base.bit_length,
                    public_integer: None,
                    elements: None,
                }
            }
            AstNode::FieldAccess { object, .. } => {
                self.eval_expr(object, env, demand, call_stack);
                AbstractValue::unknown()
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                self.eval_expr(condition, env, demand, call_stack);
                let (then_demand, then_value) = self.eval_expr_branch(then_branch, env, call_stack);
                let (else_demand, else_value) = match else_branch {
                    Some(else_branch) => self.eval_expr_branch(else_branch, env, call_stack),
                    None => (PreprocessingDemand::default(), AbstractValue::unknown()),
                };
                add_demand(demand, &max_demand(then_demand, else_demand));
                merge_value(then_value, else_value)
            }
            AstNode::Block(statements) => {
                // An expression block: last expression is its value.
                let mut last = AbstractValue::unknown();
                for statement in statements {
                    last = self.eval_expr(statement, env, demand, call_stack);
                }
                last
            }
            AstNode::TupleLiteral(elements) | AstNode::SetLiteral(elements) => {
                for element in elements {
                    self.eval_expr(element, env, demand, call_stack);
                }
                AbstractValue::unknown()
            }
            AstNode::Return { value, .. } => match value {
                Some(value) => self.eval_expr(value, env, demand, call_stack),
                None => AbstractValue::unknown(),
            },
            // Any construct we do not specifically model: descend into its
            // children so embedded calls/ops are still counted, and report an
            // unknown value.
            _ => {
                for child in child_expressions(node) {
                    self.eval_expr(child, env, demand, call_stack);
                }
                AbstractValue::unknown()
            }
        }
    }

    /// Evaluate a branch of an `if`-expression in isolation, returning the
    /// branch's demand and value so the caller can take the per-branch maximum.
    fn eval_expr_branch(
        &mut self,
        node: &AstNode,
        env: &mut Env,
        call_stack: &mut Vec<String>,
    ) -> (PreprocessingDemand, AbstractValue) {
        let mut branch_demand = PreprocessingDemand::default();
        let mut branch_env = env.clone();
        let value = self.eval_expr(node, &mut branch_env, &mut branch_demand, call_stack);
        (branch_demand, value)
    }

    fn eval_binary_operation(
        &mut self,
        op: &str,
        left: &AstNode,
        right: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> AbstractValue {
        let left_value = self.eval_expr(left, env, demand, call_stack);
        let right_value = self.eval_expr(right, env, demand, call_stack);

        match op {
            // secret * secret consumes one Beaver triple. secret*public is free.
            // Secret-bool `and`/`or`/`xor` are each one multiplication over the
            // prime field (`a xor b = a + b - 2ab`), so they cost one triple too.
            "*" | "and" | "or" | "xor"
                if left_value.secrecy == Secrecy::Secret
                    && right_value.secrecy == Secrecy::Secret
                    && !(left_value.public_share && left_value.frac_bits.is_none())
                    && !(right_value.public_share && right_value.frac_bits.is_none()) =>
            {
                demand.add(1, 0, 0, 0);
            }
            // secret fixed-point division runs the truncation protocol: `f`
            // random bits + 1 random int, where `f` is the left operand's
            // fractional-bit count.
            "/" if left_value.secrecy == Secrecy::Secret => {
                let f = left_value
                    .frac_bits
                    .unwrap_or(DEFAULT_FIXED_POINT_FRACTIONAL_BITS) as u64;
                demand.add(0, 0, f, 1);
                demand.require_prandint_bits(DEFAULT_FIXED_POINT_TOTAL_BITS);
            }
            _ => {}
        }

        // Fold constant integer arithmetic for loop-bound evaluation.
        let int = match (op, left_value.int, right_value.int) {
            ("+", Some(a), Some(b)) => a.checked_add(b),
            ("-", Some(a), Some(b)) => a.checked_sub(b),
            ("*", Some(a), Some(b)) => a.checked_mul(b),
            ("/", Some(a), Some(b)) if b != 0 => Some(a / b),
            ("mod" | "%", Some(a), Some(b)) if b != 0 => Some(a % b),
            _ => None,
        };

        let public_integer = if left_value.public_share && right_value.public_share {
            match (op, left_value.public_integer, right_value.public_integer) {
                ("*", Some(left), Some(right)) => left.checked_mul(right),
                ("and", Some(left), Some(right)) => Some(i64::from(left != 0 && right != 0)),
                ("or", Some(left), Some(right)) => Some(i64::from(left != 0 || right != 0)),
                ("xor", Some(left), Some(right)) => Some(i64::from((left != 0) ^ (right != 0))),
                _ => None,
            }
        } else {
            None
        };

        AbstractValue {
            len: Len::Unknown,
            secrecy: left_value.secrecy.join_arith(right_value.secrecy),
            public_share: left_value.public_share
                && right_value.public_share
                && left_value.frac_bits.is_none()
                && right_value.frac_bits.is_none(),
            int,
            frac_bits: left_value.frac_bits.or(right_value.frac_bits),
            bit_length: left_value.bit_length.or(right_value.bit_length),
            public_integer,
            elements: None,
        }
    }

    fn eval_function_call(
        &mut self,
        function: &AstNode,
        arguments: &[AstNode],
        resolved_return_type: Option<&SymbolType>,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> AbstractValue {
        let AstNode::Identifier(raw_name, _) = function else {
            // Indirect call: evaluate the callee and arguments for embedded
            // demand; result unknown.
            self.eval_expr(function, env, demand, call_stack);
            for argument in arguments {
                self.eval_expr(argument, env, demand, call_stack);
            }
            return AbstractValue::unknown();
        };

        // Map source-level builtin aliases to their VM symbol, mirroring
        // codegen. UFCS lowers some builtin-object calls to an unqualified
        // method name (`Share.add(...)` -> `add(...)`); resolve that form by
        // its semantic return type when it does not name a user function.
        let registry = crate::builtin_registry::builtin_registry();
        let name = registry
            .vm_symbol_for_call(raw_name)
            .map(str::to_string)
            .or_else(|| {
                if self.functions.contains_key(raw_name) {
                    return None;
                }
                let expected = resolved_return_type?;
                let mut candidates = registry
                    .objects
                    .values()
                    .filter_map(|object| object.methods.get(raw_name))
                    .filter(|method| &method.return_type == expected)
                    .map(|method| method.qualified_name.as_str());
                let candidate = candidates.next()?;
                candidates.next().is_none().then(|| candidate.to_string())
            })
            .unwrap_or_else(|| raw_name.to_string());

        // Pre-evaluate argument abstract values (also accumulates embedded
        // demand from nested calls/ops).
        let arg_values: Vec<AbstractValue> = arguments
            .iter()
            .map(|argument| self.eval_expr(argument, env, demand, call_stack))
            .collect();

        match name.as_str() {
            // --- Operations that consume preprocessing material ---------------
            "Share.mul" => {
                let left = arg_values.first();
                let right = arg_values.get(1);
                let left_is_local_constant =
                    left.is_some_and(|value| value.public_share && value.frac_bits.is_none());
                let right_is_local_constant =
                    right.is_some_and(|value| value.public_share && value.frac_bits.is_none());
                if !left_is_local_constant && !right_is_local_constant {
                    preprocessing_diagnostic(format_args!(
                        "interactive Share.mul in {}: left={left:?}, right={right:?}",
                        call_stack.join(" -> ")
                    ));
                    demand.add(1, 0, 0, 0);
                }
                let bit_length = left
                    .and_then(|value| value.bit_length)
                    .or_else(|| right.and_then(|value| value.bit_length));
                if left_is_local_constant && right_is_local_constant {
                    match left
                        .and_then(|value| value.public_integer)
                        .zip(right.and_then(|value| value.public_integer))
                        .and_then(|(left, right)| left.checked_mul(right))
                        .and_then(|value| AbstractValue::public_integral_share(bit_length, value))
                    {
                        Some(value) => value,
                        None => {
                            let mut value = AbstractValue::public_share(None);
                            value.bit_length = bit_length;
                            value
                        }
                    }
                } else {
                    AbstractValue::secret_with_bit_length(bit_length)
                }
            }
            "Share.batch_mul" => {
                let input_len = arg_values
                    .first()
                    .map(|value| value.len.clone())
                    .unwrap_or(Len::Unknown);
                let left = arg_values.first();
                let right = arg_values.get(1);
                let left_is_local_constant =
                    left.is_some_and(|value| value.public_share && value.frac_bits.is_none());
                let right_is_local_constant =
                    right.is_some_and(|value| value.public_share && value.frac_bits.is_none());
                let exact_products = left
                    .and_then(|value| value.elements.as_ref())
                    .zip(right.and_then(|value| value.elements.as_ref()))
                    .filter(|(left, right)| left.len() == right.len())
                    .map(|(left, right)| {
                        left.iter()
                            .zip(right.iter())
                            .map(|(left, right)| {
                                let left_local = left.public_share && left.frac_bits.is_none();
                                let right_local = right.public_share && right.frac_bits.is_none();
                                let bit_length = left.bit_length.or(right.bit_length);
                                let mut value = if left_local && right_local {
                                    left.public_integer
                                        .zip(right.public_integer)
                                        .and_then(|(left, right)| left.checked_mul(right))
                                        .and_then(|value| {
                                            AbstractValue::public_integral_share(bit_length, value)
                                        })
                                        .unwrap_or_else(|| {
                                            let mut value = AbstractValue::public_share(None);
                                            value.bit_length = bit_length;
                                            value
                                        })
                                } else {
                                    AbstractValue::secret_with_bit_length(bit_length)
                                };
                                value.len = Len::Unknown;
                                (u64::from(!left_local && !right_local), value)
                            })
                            .collect::<Vec<_>>()
                    });
                if let Some(products) = &exact_products {
                    demand.add(products.iter().map(|(cost, _)| *cost).sum(), 0, 0, 0);
                } else if !left_is_local_constant && !right_is_local_constant {
                    match input_len.count() {
                        Some(len) => demand.add(len as u64, 0, 0, 0),
                        None => {
                            // Runtime-sized batch: provision one and flag dynamic.
                            preprocessing_diagnostic(format_args!(
                                "dynamic Share.batch_mul in {}: left={:?}, right={:?}",
                                call_stack.join(" -> "),
                                arg_values.first(),
                                arg_values.get(1)
                            ));
                            demand.add(1, 0, 0, 0);
                            demand.dynamic = true;
                        }
                    }
                }
                // Result is a list of secret shares, same length as the inputs.
                AbstractValue {
                    len: input_len,
                    secrecy: Secrecy::Secret,
                    public_share: exact_products.as_ref().map_or(
                        left_is_local_constant && right_is_local_constant,
                        |products| products.iter().all(|(_, value)| value.public_share),
                    ),
                    int: None,
                    frac_bits: None,
                    bit_length: None,
                    public_integer: None,
                    elements: exact_products.map(|products| {
                        ExactElements::shared(
                            products.into_iter().map(|(_, value)| value).collect(),
                        )
                    }),
                }
            }

            // --- Length / iteration builtins ---------------------------------
            "len" | "array_length" => {
                match arg_values.first().and_then(|value| value.len.count()) {
                    Some(len) => AbstractValue::clear_int(len as u64),
                    None => AbstractValue::clear(),
                }
            }

            // --- List mutators: update the tracked length of the receiver -----
            // The appended/inserted element is the call's last argument; its
            // shape and secrecy are folded into the receiver list.
            "append" | "array_push" | "insert" => {
                let element = arg_values.last().cloned();
                let element_secrecy = element.as_ref().map(|value| value.secrecy);
                let element_public_share = element.as_ref().map(|value| value.public_share);
                let element_shape = element.as_ref().map(|value| value.len.clone());
                // `arg_values[0]` is a clone of the receiver. Keeping it alive
                // across the mutation would make every append copy the entire
                // accumulated vector through `Arc::make_mut`.
                drop(arg_values);
                self.list_grow(
                    arguments.first(),
                    1,
                    element_secrecy,
                    element_public_share,
                    element_shape,
                    element.map(|element| ExactElements::shared(vec![element])),
                    env,
                );
                AbstractValue::clear()
            }
            "extend" => {
                let source = arg_values.get(1).cloned();
                let element_secrecy = source.as_ref().map(|value| value.secrecy);
                let element_public_share = source.as_ref().map(|value| value.public_share);
                let count = source.as_ref().and_then(|value| value.len.count());
                let element_shape = source.as_ref().map(|value| value.len.element());
                let exact_elements = source.and_then(|value| value.elements);
                // Release the separately evaluated receiver snapshot before
                // mutating it; the source snapshot remains alive by necessity.
                drop(arg_values);
                match count {
                    Some(n) => self.list_grow(
                        arguments.first(),
                        n,
                        element_secrecy,
                        element_public_share,
                        element_shape,
                        exact_elements,
                        env,
                    ),
                    None => self.list_make_unknown(arguments.first(), env),
                }
                AbstractValue::clear()
            }

            // `copy` creates a distinct list object but preserves the complete
            // abstract value shape. The O3 multiply batcher seeds each fused
            // operand accumulator with `copy(first_operand)` and then extends
            // it; losing the seed length here makes an otherwise fully static
            // `Share.batch_mul` appear runtime-sized, forcing online top-ups.
            "copy" => arg_values
                .first()
                .cloned()
                .unwrap_or_else(AbstractValue::unknown),

            // --- List/object constructors ------------------------------------
            "create_array" => AbstractValue {
                len: Len::flat(0),
                secrecy: Secrecy::Unknown,
                public_share: false,
                int: None,
                frac_bits: None,
                bit_length: None,
                public_integer: None,
                elements: Some(ExactElements::shared(Vec::new())),
            },
            "create_object"
            | "set_field"
            | "print"
            | "to_string"
            | "assert"
            | "MpcOutput.send_to_client"
            | "Share.send_to_client" => AbstractValue::clear(),
            "get_field" => {
                if let Some(value) = arg_values
                    .get(1)
                    .and_then(|index| index.int)
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| arg_values.first()?.elements.as_ref()?.get(index))
                {
                    return value.clone();
                }
                arg_values
                    .first()
                    .map(|collection| AbstractValue {
                        len: collection.len.element(),
                        secrecy: collection.secrecy,
                        public_share: collection.public_share,
                        int: None,
                        frac_bits: collection.frac_bits,
                        bit_length: collection.bit_length,
                        public_integer: None,
                        elements: None,
                    })
                    .unwrap_or_else(AbstractValue::unknown)
            }
            "slice" => {
                let source = arg_values.first();
                let len = match (
                    arg_values.get(1).and_then(|value| value.int),
                    arg_values.get(2).and_then(|value| value.int),
                ) {
                    (Some(start), Some(end)) if end >= start => Len::Known {
                        len: (end - start) as usize,
                        elem: Box::new(
                            source
                                .map(|value| value.len.element())
                                .unwrap_or(Len::Unknown),
                        ),
                    },
                    _ => Len::Unknown,
                };
                AbstractValue {
                    len,
                    secrecy: source
                        .map(|value| value.secrecy)
                        .unwrap_or(Secrecy::Unknown),
                    public_share: source.is_some_and(|value| value.public_share),
                    int: None,
                    frac_bits: source.and_then(|value| value.frac_bits),
                    bit_length: None,
                    public_integer: None,
                    elements: source
                        .and_then(|value| value.elements.as_ref())
                        .zip(arg_values.get(1).and_then(|value| value.int))
                        .zip(arg_values.get(2).and_then(|value| value.int))
                        .and_then(|((elements, start), end)| {
                            let start = usize::try_from(start).ok()?;
                            let end = usize::try_from(end).ok()?;
                            elements
                                .get(start..end)
                                .map(|elements| ExactElements::shared(elements.to_vec()))
                        }),
                }
            }
            "contains" => AbstractValue::clear(),

            // --- Client input: a secret scalar share -------------------------
            "ClientStore.take_share" | "ClientStore.take_share_fixed" => AbstractValue::secret(),
            "ClientStore.take_share_bool" => AbstractValue::secret_with_bit_length(Some(1)),

            // --- Operations that consume random preprocessing material -------
            // random_field always uses the random-share pool. A typed
            // `Share.random()` is lowered to random_int(bit_length), whose
            // backing pool depends on the selected runtime backend.
            "Share.random_field" => {
                demand.add(0, 1, 0, 0);
                AbstractValue::secret()
            }
            "Share.random" => {
                match self.mpc_backend {
                    MpcBackend::HoneyBadger => {
                        demand.add(0, 0, 0, 1);
                        let bit_width = resolved_return_type
                            .and_then(secret_scalar_bit_width)
                            .unwrap_or(DEFAULT_FIXED_POINT_TOTAL_BITS);
                        demand.require_prandint_bits(bit_width);
                    }
                    MpcBackend::Avss => demand.add(0, 1, 0, 0),
                }
                AbstractValue::secret()
            }
            "Share.random_int" => {
                match self.mpc_backend {
                    MpcBackend::HoneyBadger => {
                        demand.add(0, 0, 0, 1);
                        let bit_width = arg_values
                            .first()
                            .and_then(|value| value.int)
                            .and_then(|value| usize::try_from(value).ok());
                        match bit_width {
                            Some(bit_width) => demand.require_prandint_bits(bit_width),
                            None => {
                                preprocessing_diagnostic(format_args!(
                                    "dynamic Share.random_int width in {}",
                                    call_stack.join(" -> ")
                                ));
                                demand.require_prandint_bits(DEFAULT_FIXED_POINT_TOTAL_BITS);
                                demand.dynamic = true;
                            }
                        }
                    }
                    MpcBackend::Avss => demand.add(0, 1, 0, 0),
                }
                AbstractValue::secret()
            }

            // --- Free MPC builtins (secrecy effects only, no demand) ---------
            "Share.add" | "Share.sub" => {
                let left = arg_values.first();
                let right = arg_values.get(1);
                let bit_length = left
                    .and_then(|value| value.bit_length)
                    .or_else(|| right.and_then(|value| value.bit_length));
                let result = left
                    .filter(|value| value.public_share)
                    .and_then(|value| value.public_integer)
                    .zip(
                        right
                            .filter(|value| value.public_share)
                            .and_then(|value| value.public_integer),
                    )
                    .and_then(|(left, right)| match name.as_str() {
                        "Share.add" => left.checked_add(right),
                        "Share.sub" => left.checked_sub(right),
                        _ => unreachable!(),
                    })
                    .and_then(|value| AbstractValue::public_integral_share(bit_length, value));
                result.unwrap_or_else(|| AbstractValue::secret_with_bit_length(bit_length))
            }
            "Share.mul_scalar" | "Share.add_constant" | "Share.add_scalar" => {
                let share = arg_values.first();
                let scalar = arg_values
                    .get(1)
                    .and_then(|value| value.int)
                    .and_then(|value| i64::try_from(value).ok());
                let bit_length = share.and_then(|value| value.bit_length);
                let result = share
                    .filter(|value| value.public_share)
                    .and_then(|value| value.public_integer)
                    .zip(scalar)
                    .and_then(|(share, scalar)| match name.as_str() {
                        "Share.mul_scalar" => share.checked_mul(scalar),
                        "Share.add_constant" | "Share.add_scalar" => share.checked_add(scalar),
                        _ => unreachable!(),
                    })
                    .and_then(|value| AbstractValue::public_integral_share(bit_length, value));
                result.unwrap_or_else(|| AbstractValue::secret_with_bit_length(bit_length))
            }
            "Share.neg" => {
                let share = arg_values.first();
                let bit_length = share.and_then(|value| value.bit_length);
                share
                    .filter(|value| value.public_share)
                    .and_then(|value| value.public_integer)
                    .and_then(i64::checked_neg)
                    .and_then(|value| AbstractValue::public_integral_share(bit_length, value))
                    .unwrap_or_else(|| AbstractValue::secret_with_bit_length(bit_length))
            }
            "Share.from_clear"
            | "Share.from_clear_int"
            | "Share.from_clear_uint"
            | "Share.from_clear_fixed" => {
                let frac_bits = if name == "Share.from_clear_fixed" {
                    arg_values
                        .get(2)
                        .and_then(|value| value.int)
                        .and_then(|value| usize::try_from(value).ok())
                        .or(Some(DEFAULT_FIXED_POINT_FRACTIONAL_BITS))
                } else if resolved_return_type
                    .is_some_and(|ty| matches!(ty.underlying_type(), SymbolType::Fixed { .. }))
                {
                    Some(DEFAULT_FIXED_POINT_FRACTIONAL_BITS)
                } else {
                    None
                };
                let bit_length =
                    if name == "Share.from_clear_int" || name == "Share.from_clear_uint" {
                        arg_values
                            .get(1)
                            .and_then(|value| value.int)
                            .and_then(|value| usize::try_from(value).ok())
                    } else if name == "Share.from_clear" {
                        Some(64)
                    } else {
                        None
                    };
                let public_integer = (frac_bits.is_none())
                    .then(|| arg_values.first().and_then(|value| value.int))
                    .flatten()
                    .and_then(|value| i64::try_from(value).ok())
                    .map(|value| {
                        if bit_length == Some(1) {
                            i64::from(value != 0)
                        } else {
                            value
                        }
                    });
                let mut value = AbstractValue::public_share(frac_bits);
                value.bit_length = bit_length;
                value.public_integer = public_integer;
                value
            }
            "Share.open" => AbstractValue::clear(),

            // --- User functions: recurse with the call's argument shapes -----
            _ => {
                if let Some(info) = self.functions.get(name.as_str()).copied() {
                    let result = self.analyze_call(&name, info, &arg_values, call_stack);
                    add_demand(demand, &result.demand);
                    result.ret
                } else {
                    // Unknown function with no analysable body. We have already
                    // counted demand inside its arguments; its own body is
                    // opaque, so report unknown (do not over-count).
                    preprocessing_diagnostic(format_args!(
                        "unknown call {name} in {}",
                        call_stack.join(" -> ")
                    ));
                    AbstractValue::unknown()
                }
            }
        }
    }

    /// Grow the tracked length of the list variable named by `receiver` by `n`
    /// (when its current length is statically known), recording the appended
    /// element's shape (so the receiver becomes a list-of-known-shape) and
    /// folding the element's secrecy into the list's element secrecy.
    fn list_grow(
        &mut self,
        receiver: Option<&AstNode>,
        n: usize,
        element_secrecy: Option<Secrecy>,
        element_public_share: Option<bool>,
        element_shape: Option<Len>,
        exact_elements: Option<Arc<ExactElements>>,
        env: &mut Env,
    ) {
        if let Some(AstNode::Identifier(name, _)) = receiver {
            if let Some(value) = env.get_mut(name) {
                let was_empty = matches!(&value.len, Len::Known { len: 0, .. });
                value.len = match &value.len {
                    Len::Known { len, elem } => {
                        // Keep the element shape if it agrees with the appended
                        // element's shape; otherwise the list is ragged.
                        let new_elem = match (element_shape, elem.as_ref()) {
                            (Some(appended), _) if *len == 0 => appended,
                            (Some(appended), existing) if appended == *existing => appended,
                            (Some(_), _) => Len::Unknown,
                            (None, existing) => existing.clone(),
                        };
                        Len::Known {
                            len: len + n,
                            elem: Box::new(new_elem),
                        }
                    }
                    Len::Unknown => Len::Unknown,
                };
                if let Some(element_secrecy) = element_secrecy {
                    // A list that has held a secret element has secret elements.
                    value.secrecy = match (value.secrecy, element_secrecy) {
                        (Secrecy::Secret, _) | (_, Secrecy::Secret) => Secrecy::Secret,
                        (Secrecy::Clear, Secrecy::Clear) => Secrecy::Clear,
                        _ => Secrecy::Unknown,
                    };
                }
                if let Some(element_public_share) = element_public_share {
                    value.public_share = if was_empty {
                        element_public_share
                    } else {
                        value.public_share && element_public_share
                    };
                } else {
                    value.public_share = false;
                }
                match (&mut value.elements, exact_elements) {
                    (Some(elements), Some(appended)) if appended.len() == n => {
                        self.work.aggregate_mutations =
                            self.work.aggregate_mutations.saturating_add(1);
                        self.work.aggregate_lanes_appended = self
                            .work
                            .aggregate_lanes_appended
                            .saturating_add(appended.len() as u64);
                        if Arc::strong_count(elements) > 1 {
                            self.work.aggregate_lanes_copied = self
                                .work
                                .aggregate_lanes_copied
                                .saturating_add(elements.len() as u64);
                        }
                        ExactElements::values_mut(elements).extend(appended.iter().cloned());
                    }
                    (elements, _) => *elements = None,
                }
            }
        }
    }

    /// Mark the list variable named by `receiver` as having unknown length.
    fn list_make_unknown(&self, receiver: Option<&AstNode>, env: &mut Env) {
        if let Some(AstNode::Identifier(name, _)) = receiver {
            if let Some(value) = env.get_mut(name) {
                value.len = Len::Unknown;
                value.elements = None;
            }
        }
    }
}

fn single_append_loop_body(body: &AstNode) -> Option<(&AstNode, &AstNode)> {
    let statement = match body {
        AstNode::Block(statements) if statements.len() == 1 => &statements[0],
        AstNode::Block(_) => return None,
        statement => statement,
    };
    let statement = match statement {
        AstNode::DiscardStatement { expression, .. } => expression.as_ref(),
        statement => statement,
    };
    let AstNode::FunctionCall {
        function,
        arguments,
        ..
    } = statement
    else {
        return None;
    };
    let AstNode::Identifier(name, _) = function.as_ref() else {
        return None;
    };
    if !matches!(name.as_str(), "append" | "array_push") || arguments.len() != 2 {
        return None;
    }
    Some((&arguments[0], &arguments[1]))
}

fn node_references_identifier(node: &AstNode, target: &str) -> bool {
    if matches!(node, AstNode::Identifier(name, _) if name == target) {
        return true;
    }
    let mut found = false;
    crate::optimizations::for_each_child(node, &mut |child| {
        if !found {
            found = node_references_identifier(child, target);
        }
    });
    found
}

/// Semantic equality for exact lane facts. Snapshot ids deliberately make call
/// cache keys distinguish independently-created aggregates; this proof instead
/// needs value equality, so nested exact aggregates are compared recursively.
fn abstract_values_equivalent(left: &AbstractValue, right: &AbstractValue) -> bool {
    left.len == right.len
        && left.secrecy == right.secrecy
        && left.public_share == right.public_share
        && left.int == right.int
        && left.frac_bits == right.frac_bits
        && left.bit_length == right.bit_length
        && left.public_integer == right.public_integer
        && match (&left.elements, &right.elements) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                Arc::ptr_eq(left, right)
                    || (left.len() == right.len()
                        && left
                            .iter()
                            .zip(right.iter())
                            .all(|(left, right)| abstract_values_equivalent(left, right)))
            }
            _ => false,
        }
}

/// Prove that `expression` has one abstract value for every induction value in
/// `[start, start + count)`. Direct induction-variable indexing is uniform only
/// when every selected exact lane is semantically equal. Any other use of the
/// induction variable fails closed. Mutating calls are excluded because their
/// caller environment would not be iteration-invariant.
fn expression_is_uniform_over_range(
    expression: &AstNode,
    loop_var: &str,
    start: u64,
    count: u64,
    env: &Env,
) -> bool {
    if count == 0 {
        return true;
    }
    if let AstNode::IndexAccess { base, index, .. } = expression {
        if matches!(index.as_ref(), AstNode::Identifier(name, _) if name == loop_var) {
            let AstNode::Identifier(base_name, _) = base.as_ref() else {
                return false;
            };
            let Some(elements) = env.get(base_name).and_then(|value| value.elements.as_ref())
            else {
                return false;
            };
            let Some(end) = start.checked_add(count) else {
                return false;
            };
            let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
                return false;
            };
            let Some(selected) = elements.get(start..end) else {
                return false;
            };
            return selected.split_first().is_none_or(|(first, rest)| {
                rest.iter()
                    .all(|element| abstract_values_equivalent(first, element))
            });
        }
    }
    if matches!(expression, AstNode::Identifier(name, _) if name == loop_var) {
        return count == 1;
    }
    if let AstNode::FunctionCall {
        function,
        arguments: _,
        ..
    } = expression
    {
        if matches!(
            function.as_ref(),
            AstNode::Identifier(name, _)
                if matches!(
                    name.as_str(),
                    "append" | "array_push" | "insert" | "extend" | "pop" | "remove"
                )
        ) {
            return false;
        }
    }
    let mut uniform = true;
    crate::optimizations::for_each_child(expression, &mut |child| {
        if uniform {
            uniform = expression_is_uniform_over_range(child, loop_var, start, count, env);
        }
    });
    uniform
}

/// Fold a freshly observed return value into a function's accumulating return
/// value. The first `return` seeds it exactly (so a known length is preserved);
/// subsequent returns merge per-element.
fn merge_into_ret(ret: &mut Option<AbstractValue>, value: Option<AbstractValue>) {
    *ret = merge_opt_ret(ret.clone(), value);
}

/// Combine two optional return values: `None` is "no return on this path".
fn merge_opt_ret(a: Option<AbstractValue>, b: Option<AbstractValue>) -> Option<AbstractValue> {
    match (a, b) {
        (Some(a), Some(b)) => Some(merge_value(a, b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Merge two abstract values that may both flow to the same use (e.g. two `if`
/// branches or two `return`s).
fn merge_value(a: AbstractValue, b: AbstractValue) -> AbstractValue {
    let len = if a.len == b.len { a.len } else { Len::Unknown };
    let int = match (a.int, b.int) {
        (Some(x), Some(y)) if x == y => Some(x),
        _ => None,
    };
    let elements = match (a.elements.clone(), b.elements.clone()) {
        (Some(left), Some(right)) if left.len() == right.len() => Some(ExactElements::shared(
            left.iter()
                .zip(right.iter())
                .map(|(left, right)| merge_value(left.clone(), right.clone()))
                .collect(),
        )),
        _ => None,
    };
    AbstractValue {
        len,
        secrecy: a.secrecy.merge_branch(b.secrecy),
        public_share: a.public_share && b.public_share,
        int,
        frac_bits: if a.frac_bits == b.frac_bits {
            a.frac_bits
        } else {
            None
        },
        bit_length: if a.bit_length == b.bit_length {
            a.bit_length
        } else {
            None
        },
        public_integer: if a.public_integer == b.public_integer {
            a.public_integer
        } else {
            None
        },
        elements,
    }
}

fn assignment_root(node: &AstNode) -> Option<&str> {
    match node {
        AstNode::Identifier(name, _) => Some(name),
        AstNode::IndexAccess { base, .. } => assignment_root(base),
        AstNode::FieldAccess { object, .. } => assignment_root(object),
        _ => None,
    }
}

fn update_exact_aggregate_assignment(
    env: &mut Env,
    target: &AstNode,
    assigned: &AbstractValue,
) -> bool {
    fn collect_path(node: &AstNode, env: &Env, indices: &mut Vec<usize>) -> Option<String> {
        match node {
            AstNode::Identifier(name, _) => Some(name.clone()),
            AstNode::IndexAccess { base, index, .. } => {
                let root = collect_path(base, env, indices)?;
                let index = match index.as_ref() {
                    AstNode::Literal {
                        value: Value::Int { value, .. },
                        ..
                    } => usize::try_from(*value).ok()?,
                    AstNode::Identifier(name, _) => env
                        .get(name)
                        .and_then(|value| value.int)
                        .and_then(|value| usize::try_from(value).ok())?,
                    _ => return None,
                };
                indices.push(index);
                Some(root)
            }
            // Object-field aliasing is not represented lane-by-lane.
            AstNode::FieldAccess { .. } => None,
            _ => None,
        }
    }

    fn refresh_aggregate(value: &mut AbstractValue) {
        let Some(elements) = value.elements.as_ref() else {
            return;
        };
        value.public_share = !elements.is_empty() && elements.iter().all(|item| item.public_share);
        value.secrecy = elements.iter().fold(Secrecy::Clear, |secrecy, item| {
            secrecy.join_arith(item.secrecy)
        });
    }

    fn replace_at_path(
        aggregate: &mut AbstractValue,
        indices: &[usize],
        assigned: &AbstractValue,
    ) -> bool {
        let Some((&index, rest)) = indices.split_first() else {
            *aggregate = assigned.clone();
            return true;
        };
        let Some(element) = aggregate
            .elements
            .as_mut()
            .and_then(|elements| ExactElements::values_mut(elements).get_mut(index))
        else {
            return false;
        };
        if !replace_at_path(element, rest, assigned) {
            return false;
        }
        refresh_aggregate(aggregate);
        true
    }

    let mut indices = Vec::new();
    let Some(root) = collect_path(target, env, &mut indices) else {
        return false;
    };
    if indices.is_empty() {
        return false;
    }
    env.get_mut(&root)
        .is_some_and(|aggregate| replace_at_path(aggregate, &indices, assigned))
}

/// One canonical `while` counter step, extracted from the body's top level.
#[derive(Clone, Copy)]
enum WhileStep {
    Add(u64),
    Sub(u64),
    Mul(u64),
}

/// `(var, cmp, bound_expr)` of a `while v OP bound:` condition, if that shape.
fn while_condition_parts(condition: &AstNode) -> Option<(&str, &str, &AstNode)> {
    if let AstNode::BinaryOperation {
        op, left, right, ..
    } = condition
    {
        if matches!(op.as_str(), "<" | "<=" | ">" | ">=") {
            if let AstNode::Identifier(name, _) = left.as_ref() {
                return Some((name.as_str(), op.as_str(), right));
            }
        }
    }
    None
}

/// The single counter-step assignment for `var` in `body`, or `None` when the
/// body assigns `var` zero times, more than once, somewhere nested, or in a
/// non-`v = v ± lit` / `v = v * lit` shape.
fn while_step(body: &AstNode, var: &str) -> Option<WhileStep> {
    fn count_assignments(node: &AstNode, var: &str, n: &mut usize) {
        if let AstNode::Assignment { target, .. } = node {
            if matches!(target.as_ref(), AstNode::Identifier(name, _) if name == var) {
                *n += 1;
            }
        }
        crate::optimizations::for_each_child(node, &mut |child| count_assignments(child, var, n));
    }

    let statements = match body {
        AstNode::Block(statements) => statements.as_slice(),
        other => std::slice::from_ref(other),
    };

    let mut total = 0usize;
    for statement in statements {
        count_assignments(statement, var, &mut total);
    }
    if total != 1 {
        return None;
    }

    for statement in statements {
        let AstNode::Assignment { target, value, .. } = statement else {
            continue;
        };
        if !matches!(target.as_ref(), AstNode::Identifier(name, _) if name == var) {
            continue;
        }
        let AstNode::BinaryOperation {
            op, left, right, ..
        } = value.as_ref()
        else {
            return None;
        };
        let lit = |node: &AstNode| -> Option<u64> {
            if let AstNode::Literal {
                value: Value::Int { value, .. },
                ..
            } = node
            {
                u64::try_from(*value).ok()
            } else {
                None
            }
        };
        let var_side = |node: &AstNode| -> bool {
            matches!(node, AstNode::Identifier(name, _) if name == var)
        };
        return match op.as_str() {
            "+" if var_side(left) => lit(right).filter(|s| *s > 0).map(WhileStep::Add),
            "+" if var_side(right) => lit(left).filter(|s| *s > 0).map(WhileStep::Add),
            "-" if var_side(left) => lit(right).filter(|s| *s > 0).map(WhileStep::Sub),
            "*" if var_side(left) => lit(right).filter(|k| *k >= 2).map(WhileStep::Mul),
            "*" if var_side(right) => lit(left).filter(|k| *k >= 2).map(WhileStep::Mul),
            _ => None,
        };
    }
    None
}

/// Add `addend` into `target` (saturating), preserving/propagating `dynamic`.
fn add_demand(target: &mut PreprocessingDemand, addend: &PreprocessingDemand) {
    target.add(
        addend.triples,
        addend.randoms,
        addend.prandbits,
        addend.prandints,
    );
    target.dynamic |= addend.dynamic;
    target.prandint_bits = target.prandint_bits.max(addend.prandint_bits);
}

/// Multiply a demand by an iteration count (saturating).
fn scale_demand(demand: &PreprocessingDemand, count: u64) -> PreprocessingDemand {
    PreprocessingDemand {
        triples: demand.triples.saturating_mul(count),
        randoms: demand.randoms.saturating_mul(count),
        prandbits: demand.prandbits.saturating_mul(count),
        prandints: demand.prandints.saturating_mul(count),
        prandint_bits: demand.prandint_bits,
        dynamic: demand.dynamic,
    }
}

/// Propagate the list-length effects of one symbolic loop iteration back into
/// the enclosing `env`, scaled by the loop's iteration `count`. For each list
/// variable visible before the loop, the body's net per-iteration length change
/// is multiplied by `count` and applied to the pre-loop length. New bindings
/// introduced inside the loop body are loop-local and not propagated.
fn apply_loop_length_growth(env: &mut Env, body_env: &Env, count: u64) {
    for (name, before) in env.clone().iter() {
        let Some(after) = body_env.get(name) else {
            continue;
        };
        let new_len = if count == 0 {
            before.len.clone()
        } else {
            match (&before.len, &after.len) {
                (
                    Len::Known { len: start, .. },
                    Len::Known {
                        len: end,
                        elem: end_elem,
                    },
                ) => {
                    let delta = *end as i128 - *start as i128;
                    let total = *start as i128 + delta * count as i128;
                    if total >= 0 {
                        // Preserve the per-iteration element shape (e.g. each
                        // appended byte stays length 8).
                        Len::Known {
                            len: total as usize,
                            elem: end_elem.clone(),
                        }
                    } else {
                        Len::Unknown
                    }
                }
                // The body made the length unknown (or it always was): stays unknown.
                (_, Len::Unknown) => Len::Unknown,
                // The list did not exist with a known length before but does now:
                // we cannot scale it reliably, so treat as unknown.
                (Len::Unknown, Len::Known { .. }) => Len::Unknown,
            }
        };
        if let Some(slot) = env.get_mut(name) {
            slot.len = new_len;
            if count > 0 {
                slot.secrecy = after.secrecy;
                slot.public_share = after.public_share;
                slot.frac_bits = after.frac_bits;
                // The scalable loop summary knows the final length and uniform
                // element facts, but not an exact lane vector for repeated
                // mutations. Dropping the stale pre-loop vector makes later
                // batches use the proven length instead of seeing (for example)
                // the original empty list as an exact zero-lane operand.
                slot.elements = if count == 1 {
                    after.elements.clone()
                } else {
                    None
                };
                // A scalar constant that the symbolic iteration did not change
                // is a loop invariant and remains foldable after any number of
                // iterations. This matters for consecutive counted loops: a
                // known `n` used by the first loop must still size the second.
                // For a value changed by the body, one iteration is exact; two
                // or more require a recurrence model we deliberately do not
                // guess at.
                slot.int = if before.int == after.int {
                    before.int
                } else if count == 1 {
                    after.int
                } else {
                    None
                };
            }
        }
    }
}

/// After an unbounded loop, any list whose length the body changed is no longer
/// statically known.
fn apply_loop_length_growth_unknown(env: &mut Env, body_env: &Env) {
    for (name, before) in env.clone().iter() {
        let Some(after) = body_env.get(name) else {
            continue;
        };
        if let Some(slot) = env.get_mut(name) {
            if before.len != after.len {
                slot.len = Len::Unknown;
            }
            slot.elements = None;
            slot.secrecy = before.secrecy.merge_branch(after.secrecy);
            slot.public_share = before.public_share && after.public_share;
            slot.frac_bits = if before.frac_bits == after.frac_bits {
                before.frac_bits
            } else {
                None
            };
            slot.int = None;
        }
    }
}

/// Whether a demand carries any preprocessing material at all.
fn has_any_material(demand: &PreprocessingDemand) -> bool {
    demand.triples > 0 || demand.randoms > 0 || demand.prandbits > 0 || demand.prandints > 0
}

/// Collect names that evaluation of `node` can introduce into the current
/// environment. Exact loop interpretation uses this small, syntax-derived set
/// to discard iteration-local bindings without scanning or cloning every
/// binding visible at the loop site.
fn collect_declared_names(node: &AstNode, names: &mut Vec<String>) {
    match node {
        AstNode::VariableDeclaration { name, .. } => names.push(name.clone()),
        // A nested function owns a separate environment and is not executed as
        // part of the containing block.
        AstNode::FunctionDefinition { .. } => return,
        _ => {}
    }
    crate::optimizations::for_each_child(node, &mut |child| collect_declared_names(child, names));
}

/// Element secrecy of a parameter, derived from its type annotation. A
/// `secret T` (scalar) or `list[secret T]` / nested-list-of-secret parameter has
/// secret elements; otherwise its elements are clear.
fn param_element_secrecy(param: &Parameter) -> Secrecy {
    if param.is_secret {
        return Secrecy::Secret;
    }
    match param.type_annotation.as_deref() {
        Some(annotation) => {
            if annotation_contains_secret(annotation) {
                Secrecy::Secret
            } else {
                Secrecy::Clear
            }
        }
        None => Secrecy::Unknown,
    }
}

/// Whether a type annotation wraps a `secret` anywhere (through `list[...]`
/// nesting), i.e. its scalar leaf is secret.
fn annotation_contains_secret(annotation: &AstNode) -> bool {
    match annotation {
        AstNode::SecretType(_) => true,
        AstNode::ListType(inner) => annotation_contains_secret(inner),
        _ => false,
    }
}

/// Bit width used when a contextual `Share.random()` is lowered to
/// `Share.random_int(width)`. This mirrors codegen so preprocessing and runtime
/// agree on the PRandInt distribution instead of provisioning a fixed width.
fn secret_scalar_bit_width(ty: &SymbolType) -> Option<usize> {
    if !ty.is_secret() {
        return None;
    }
    match ty.underlying_type() {
        SymbolType::Bool => Some(1),
        SymbolType::Fixed { bits } => Some(usize::from(*bits)),
        _ => ty.bit_width().map(usize::from),
    }
}

/// Fractional-bit count of a parameter whose leaf type is a secret fixed-point,
/// used to size the `/` truncation cost.
///
/// The AES examples operate over secret booleans, never secret fixed-point
/// division, so a precise per-parameter fractional-bit count is not needed here.
/// Returning `None` makes `/` fall back to the project default, matching the
/// previous codegen behaviour for fixed-point division.
fn param_frac_bits(_param: &Parameter) -> Option<usize> {
    None
}

/// Direct child expressions of a node, for conservative descent into constructs
/// the planner does not model explicitly.
fn child_expressions(node: &AstNode) -> Vec<&AstNode> {
    match node {
        AstNode::Assignment { target, value, .. } => vec![target, value],
        AstNode::BinaryOperation { left, right, .. } => vec![left, right],
        AstNode::UnaryOperation { operand, .. } => vec![operand],
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => std::iter::once(function.as_ref())
            .chain(arguments.iter())
            .collect(),
        AstNode::IndexAccess { base, index, .. } => vec![base, index],
        AstNode::FieldAccess { object, .. } => vec![object],
        AstNode::ListLiteral { elements, .. } => elements.iter().collect(),
        AstNode::TupleLiteral(elements) | AstNode::SetLiteral(elements) => {
            elements.iter().collect()
        }
        AstNode::Return {
            value: Some(value), ..
        } => vec![value.as_ref()],
        AstNode::DiscardStatement { expression, .. } => vec![expression],
        AstNode::Block(statements) => statements.iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile, CompilerOptions};
    use crate::errors::ErrorReporter;
    use crate::lexer::tokenize;
    use crate::parser::parse;
    use crate::semantic::analyze;
    use crate::ufcs::transform_ufcs;
    use stoffel_vm_types::compiled_binary::MpcBackend;

    fn demand_for(src: &str) -> PreprocessingDemand {
        // Compile on a dedicated large-stack thread. The compiler's parser /
        // semantic / codegen passes recurse over the AST, and the bundled AES
        // examples are large enough to exceed the test harness's small default
        // stack. (Production callers run on the main thread, whose default stack
        // is ample.)
        let src = src.to_string();
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                // Mirror the example/bindgen compile path, which emits the
                // manifest with optimization disabled. (The optimizer would
                // otherwise hoist/rewrite loop-invariant secret ops, changing
                // the consumed count.)
                let options = CompilerOptions {
                    optimize: false,
                    optimization_level: 0,
                    print_ir: false,
                    mpc_backend: MpcBackend::HoneyBadger,
                    mpc_curve: Default::default(),
                    ..Default::default()
                };
                let program = compile(&src, "t.stfl", &options).expect("compile should succeed");
                program.client_io_manifest.preprocessing_demand
            })
            .expect("failed to spawn compile thread")
            .join()
            .expect("compile thread panicked")
    }

    fn list_loop_work(iterations: usize) -> (PreprocessingDemand, PlannerWork) {
        let src = format!(
            r#"
def main() -> int64:
  var xs: list[secret bool] = []
  var ys: list[secret bool] = []
  for i in 0..{iterations}:
    xs.append(ClientStore.take_share_bool(0, i))
    ys.append(ClientStore.take_share_bool(1, i))
  var products = Share.batch_mul(xs, ys)
  return 0
"#
        );
        let tokens = tokenize(&src, "scaling.stfl").expect("synthetic source should lex");
        let ast = parse(&tokens, "scaling.stfl").expect("synthetic source should parse");
        let mut reporter = ErrorReporter::new();
        let ast = analyze(transform_ufcs(ast), &mut reporter, "scaling.stfl")
            .expect("synthetic source should pass semantic analysis");
        plan_preprocessing_demand_inner_with_work(&ast, MpcBackend::HoneyBadger)
    }

    #[test]
    fn exact_aggregate_loop_work_scales_linearly() {
        let (small_demand, small) = list_loop_work(64);
        let (medium_demand, medium) = list_loop_work(128);
        let (large_demand, large) = list_loop_work(256);

        assert_eq!(small_demand.triples, 64);
        assert_eq!(medium_demand.triples, 128);
        assert_eq!(large_demand.triples, 256);
        assert!(!small_demand.dynamic && !medium_demand.dynamic && !large_demand.dynamic);

        for (iterations, work) in [(64, small), (128, medium), (256, large)] {
            assert_eq!(work.exact_loop_iterations, iterations);
            assert_eq!(work.aggregate_mutations, iterations * 2);
            assert_eq!(work.aggregate_lanes_appended, iterations * 2);
            assert_eq!(
                work.aggregate_lanes_copied, 0,
                "growing a uniquely owned exact aggregate must not copy prior lanes"
            );
            assert_eq!(work.call_keys_built, 1);
        }

        // For a fixed loop body, expression visits have the exact form a+bN.
        // The second finite difference therefore doubles as a deterministic
        // scaling gate without relying on noisy wall-clock measurements.
        assert_eq!(
            large.expression_visits - medium.expression_visits,
            2 * (medium.expression_visits - small.expression_visits)
        );
    }

    #[test]
    fn public_share_products_cross_loops_and_calls_without_triples() {
        let src = r#"
def scale(value: secret int64, factor: secret int64) -> secret int64:
  return Share.mul(value, factor)

def main(value: secret int64) -> int64:
  var factor = Share.from_clear_int(1, 64)
  var two = Share.from_clear_int(2, 64)
  for i in 0..3:
    factor = Share.mul(factor, two)
  return Share.open(scale(value, factor))
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 0);
        assert!(!demand.dynamic);
    }

    #[test]
    fn loop_carried_public_share_transition_is_counted_per_iteration() {
        let src = r#"
def main() -> int64:
  var acc: secret bool = Share.from_clear_int(1, 1)
  var input: secret bool = ClientStore.take_share_bool(0, 0)
  for i in 0..3:
    acc = acc and input
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(
            demand.triples, 2,
            "the first public×secret product is local; the next two consume triples"
        );
        assert!(!demand.dynamic);
    }

    #[test]
    fn mixed_public_secret_batch_counts_interactive_lanes_exactly() {
        let src = r#"
def main() -> int64:
  var left = [Share.from_clear_int(1, 1), ClientStore.take_share_bool(0, 0)]
  var right = [ClientStore.take_share_bool(0, 1), ClientStore.take_share_bool(0, 2)]
  var products = Share.batch_mul(left, right)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert!(!demand.dynamic);
    }

    #[test]
    fn public_boolean_reconstruction_tracks_materialization_boundaries() {
        let src = r#"
def main() -> int64:
  var zero = Share.from_clear_int(0, 1)
  var one = Share.from_clear_int(1, 1)
  var p0 = Share.mul(zero, one)
  var still_public = Share.sub(Share.add(zero, one), Share.mul_scalar(p0, 2))
  var input = ClientStore.take_share_bool(0, 0)
  var local_product = Share.mul(still_public, input)

  var p1 = Share.mul(one, one)
  var materialized = Share.sub(Share.add(one, one), Share.mul_scalar(p1, 2))
  var interactive_product = Share.mul(materialized, input)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert!(!demand.dynamic);
    }

    #[test]
    fn counted_loop_preserves_unmodified_scalar_bounds() {
        let src = r#"
def main() -> int64:
  var n = 4
  var first: list[secret bool] = []
  for i in 0..n:
    first.append(ClientStore.take_share_bool(0, i))

  var left: list[secret bool] = []
  var right: list[secret bool] = []
  for j in 0..n:
    left.append(first[j])
    right.append(ClientStore.take_share_bool(1, j))

  var products = Share.batch_mul(left, right)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 4);
        assert!(!demand.dynamic);
    }

    #[test]
    fn fixed_public_share_multiplication_retains_protocol_demand() {
        let src = r#"
def main(value: secret fix64) -> secret fix64:
  var factor = Share.from_clear_fixed(1.5, 64, 16)
  return Share.mul(value, factor)
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert!(!demand.dynamic);
    }

    #[test]
    fn branch_replacement_cannot_leave_stale_public_provenance() {
        let src = r#"
def main(value: secret int64, replace: bool) -> secret int64:
  var maybe_public = Share.from_clear_int(3, 64)
  if replace:
    maybe_public = value
  return Share.mul(maybe_public, value)
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert!(!demand.dynamic);
    }

    /// Counted `while` loops (the only loop shape StoffelDB's codegen emits)
    /// must provision like counted `for` loops — this exact shape used to
    /// report ZERO demand with `dynamic: false` (the stale pre-loop list
    /// length made the post-loop `batch_mul` count len 0), starving the
    /// runtime preprocessing pool.
    #[test]
    fn counted_while_batch_mul_provisions_like_for() {
        let src = r#"
def main() -> int64:
  var xs: list[Share] = []
  var ys: list[Share] = []
  var i = 0
  while i < 16:
    xs.append(ClientStore.take_share(0, i))
    ys.append(ClientStore.take_share(1, i))
    i = i + 1
  var products = Share.batch_mul(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 16);
        assert!(!demand.dynamic);
    }

    /// Descending counted `while` (`i = N-1; while i >= 0: … i = i - 1`) — the
    /// restoring-divide loop shape.
    #[test]
    fn descending_while_counts_iterations() {
        let src = r#"
def main() -> int64:
  var xs: list[Share] = []
  var ys: list[Share] = []
  var j = 0
  while j < 4:
    xs.append(ClientStore.take_share(0, j))
    ys.append(ClientStore.take_share(1, j))
    j = j + 1
  var i = 7
  while i >= 0:
    var p = Share.batch_mul(xs, ys)
    i = i - 1
  return 0
"#;
        let demand = demand_for(src);
        // 8 iterations x 4-element batch_mul, plus nothing else.
        assert_eq!(demand.triples, 32);
        assert!(!demand.dynamic);
    }

    /// A non-canonical `while` (data-dependent bound) must flag `dynamic` AND
    /// poison the lengths of lists it grew, so a post-loop batch op cannot
    /// count a stale zero length as "known".
    #[test]
    fn unknown_while_flags_dynamic_via_poisoned_length() {
        let src = r#"
def main(n: int64) -> int64:
  var xs: list[Share] = []
  var ys: list[Share] = []
  var i = 0
  while i < n:
    xs.append(ClientStore.take_share(0, i))
    ys.append(ClientStore.take_share(1, i))
    i = i + 1
  var products = Share.batch_mul(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert!(demand.dynamic, "runtime-bounded while must flag dynamic");
        assert!(
            demand.triples >= 1,
            "unknown batch must provision at least one"
        );
    }

    #[test]
    fn batch_mul_over_known_literal_list() {
        let src = r#"
def main() -> int64:
  var xs: list[secret bool] = []
  for i in 0..5:
    xs.append(ClientStore.take_share_bool(0, i))
  var ys: list[secret bool] = []
  for j in 0..5:
    ys.append(ClientStore.take_share_bool(1, j))
  var products = Share.batch_mul(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 5);
        assert!(!demand.dynamic);
    }

    #[test]
    fn copy_extend_and_slice_preserve_static_batch_lengths() {
        let src = r#"
def main() -> int64:
  var xs: list[secret bool] = []
  var ys: list[secret bool] = []
  for i in 0..4:
    xs.append(ClientStore.take_share_bool(0, i))
    ys.append(ClientStore.take_share_bool(1, i))
  var lefts = copy(xs)
  var rights = copy(ys)
  lefts.extend(xs)
  rights.extend(ys)
  var products = Share.batch_mul(lefts, rights)
  var first = slice(products, 0, 4)
  var first_copy = copy(first)
  var products2 = Share.batch_mul(first_copy, first)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 12, "8-element batch plus 4-element batch");
        assert!(
            !demand.dynamic,
            "shape-preserving list plumbing must not force online top-ups"
        );
    }

    #[test]
    fn secret_xor_helper_in_literal_loop() {
        let src = r#"
def gate(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

def main() -> int64:
  var a: secret bool = ClientStore.take_share_bool(0, 0)
  var b: secret bool = ClientStore.take_share_bool(0, 1)
  for i in 0..10:
    var c: secret bool = gate(a, b)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 10);
        assert!(!demand.dynamic);
    }

    #[test]
    fn len_loop_over_literal_list() {
        let src = r#"
def helper(xs: list[secret bool], ys: list[secret bool]) -> int64:
  for i in 0..xs.len():
    var c: secret bool = xs[i] and ys[i]
  return 0

def main() -> int64:
  var xs: list[secret bool] = []
  for i in 0..7:
    xs.append(ClientStore.take_share_bool(0, i))
  var ys: list[secret bool] = []
  for j in 0..7:
    ys.append(ClientStore.take_share_bool(1, j))
  var n = helper(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 7);
        assert!(!demand.dynamic);
    }

    #[test]
    fn recursion_is_dynamic() {
        let src = r#"
def recurse(n: int64, a: secret bool, b: secret bool) -> secret bool:
  if n == 0:
    return a
  var c: secret bool = a and b
  return recurse(n - 1, c, b)

def main() -> int64:
  var a: secret bool = ClientStore.take_share_bool(0, 0)
  var b: secret bool = ClientStore.take_share_bool(0, 1)
  var r: secret bool = recurse(3, a, b)
  return 0
"#;
        let demand = demand_for(src);
        assert!(demand.dynamic);
    }

    #[test]
    fn if_takes_branch_maximum() {
        let src = r#"
def pick(flag: int64, a: secret bool, b: secret bool) -> secret bool:
  if flag == 0:
    var c: secret bool = a and b
    var d: secret bool = a xor b
    return c
  else:
    var e: secret bool = a or b
    return e

def main() -> int64:
  var a: secret bool = ClientStore.take_share_bool(0, 0)
  var b: secret bool = ClientStore.take_share_bool(0, 1)
  var r: secret bool = pick(1, a, b)
  return 0
"#;
        let demand = demand_for(src);
        // then-branch needs 2 triples (and + xor), else-branch 1 (or); max = 2.
        assert_eq!(demand.triples, 2);
        assert!(!demand.dynamic);
    }

    /// Compile each bundled AES-128 example via the real example/bindgen compile
    /// path and assert its preprocessing demand is an exact, non-dynamic count.
    /// Run with `--nocapture` to see the emitted triple counts.
    #[test]
    fn aes_examples_have_exact_static_demand() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let examples = [
            "mpc_aes128_ctr_client_io",
            "mpc_aes128_cbc_client_io",
            "mpc_aes128_transcipher",
            "mpc_aes128_secure_decrypt",
        ];
        for example in examples {
            let path = format!("{manifest_dir}/examples/{example}/main.stfl");
            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(_) => {
                    // The example is not present in this checkout; skip it.
                    eprintln!("skipping {example}: {path} not found");
                    continue;
                }
            };
            let demand = demand_for(&source);
            println!(
                "{example}: triples={} randoms={} prandbits={} prandints={} dynamic={}",
                demand.triples, demand.randoms, demand.prandbits, demand.prandints, demand.dynamic,
            );
            assert!(
                !demand.dynamic,
                "{example} demand should be statically exact (dynamic == false)"
            );
            assert!(
                demand.triples > 0,
                "{example} should consume some preprocessing triples"
            );
        }
    }
}
