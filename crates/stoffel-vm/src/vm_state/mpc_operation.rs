use super::{CompletedVmEffect, VMState};
use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::foreign_functions::ForeignFunctionError;
use crate::mpc_values::clear_share_input;
use crate::net::client_store::ClientOutputShareCount;
use crate::net::curve::clear_share_value_to_vm_value;
use crate::net::deferred_mpc::{
    defer_multiply_share, multiplication_requires_protocol, resolve_deferred_shares,
};
use crate::net::mpc_engine::{AsyncMpcEngine, MpcEngine, MpcExponentGroup, MpcPartyId};
use crate::net::share_runtime::ensure_matching_share_data_format;
use crate::runtime_hooks::{HookCallTarget, HookEvent};
use crate::runtime_instruction::{
    FetchedInstruction, RuntimeBinaryOp, RuntimeInstruction, RuntimeRegister,
};
use crate::runtime_value_ops::{bool_or_data, bool_xor_data, matching_share_pair};
use crate::standard_library::encode_output_share_list;
use crate::value_conversions::{u64_to_vm_i64, usize_to_vm_i64};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, TableRef, Value,
};
use stoffel_vm_types::registers::RegisterMoveKind;
use stoffelnet::network_utils::ClientId;

/// MPC protocol work that cannot be completed as a local VM step.
#[derive(Debug, Clone)]
pub(super) enum PendingMpcOperation {
    Input {
        clear: ClearShareInput,
        dest: RuntimeRegister,
    },
    Multiply {
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
        dest: RuntimeRegister,
    },
    BooleanBit {
        op: RuntimeBinaryOp,
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
        dest: RuntimeRegister,
    },
    Open {
        share_type: ShareType,
        share_data: ShareData,
        src: RuntimeRegister,
        dest: RuntimeRegister,
    },
    BuiltinCall(PendingMpcBuiltinCall),
}

#[derive(Debug)]
pub(super) enum CompletedMpcOperation {
    Input {
        share_type: ShareType,
        share_data: ShareData,
        dest: RuntimeRegister,
    },
    Multiply {
        share_type: ShareType,
        share_data: ShareData,
        dest: RuntimeRegister,
    },
    BooleanBit {
        op: RuntimeBinaryOp,
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
        product_data: ShareData,
        direct_result: Option<ShareData>,
        dest: RuntimeRegister,
    },
    Open {
        share_type: ShareType,
        value: ClearShareValue,
        src: RuntimeRegister,
        dest: RuntimeRegister,
    },
    BuiltinCall(CompletedMpcBuiltinCall),
}

#[derive(Debug, Clone)]
pub(super) struct PendingMpcBuiltinCall {
    return_register: RuntimeRegister,
    call_target: HookCallTarget,
    operation: PendingMpcBuiltinOperation,
}

/// One homogeneous runtime-type partition of a possibly heterogeneous
/// `Share.batch_mul` call. `output_indices` maps protocol results back to the
/// compiler-visible batch order.
#[derive(Debug, Clone)]
pub(super) struct TypedSharePairBatch {
    pub(super) share_type: ShareType,
    pub(super) output_indices: Vec<usize>,
    pub(super) left_data: Vec<ShareData>,
    pub(super) right_data: Vec<ShareData>,
}

/// One homogeneous runtime-type partition of a possibly heterogeneous
/// `Share.batch_open` call.
#[derive(Debug, Clone)]
pub(super) struct TypedShareBatch {
    pub(super) share_type: ShareType,
    pub(super) output_indices: Vec<usize>,
    pub(super) share_data: Vec<ShareData>,
}

impl PendingMpcBuiltinCall {
    pub(super) fn new(
        return_register: RuntimeRegister,
        call_target: HookCallTarget,
        operation: PendingMpcBuiltinOperation,
    ) -> Self {
        Self {
            return_register,
            call_target,
            operation,
        }
    }

    pub(crate) const fn operation(&self) -> &PendingMpcBuiltinOperation {
        &self.operation
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PendingMpcBuiltinOperation {
    InputShare {
        clear: ClearShareInput,
    },
    Mul {
        share_type: ShareType,
        left_data: ShareData,
        right_data: ShareData,
    },
    BatchMul {
        share_type: ShareType,
        left_data: Vec<ShareData>,
        right_data: Vec<ShareData>,
    },
    /// A share already combined with a public scalar locally; completes
    /// without any MPC interaction.
    LocalShare {
        share_type: ShareType,
        share_data: ShareData,
    },
    /// Batch multiplication where some pairs were share-by-public-scalar
    /// products computed locally (`precomputed[i] == Some(data)`), and the
    /// remaining `None` slots are filled, in order, from the engine batch
    /// over `left_data`/`right_data`.
    BatchMulMixed {
        share_type: ShareType,
        precomputed: Vec<Option<ShareData>>,
        left_data: Vec<ShareData>,
        right_data: Vec<ShareData>,
    },
    /// A compiler-fused batch whose lanes do not all have the same runtime
    /// `ShareType`. Each protocol call remains homogeneous, and results are
    /// restored to their original lane order. Local share-by-scalar lanes are
    /// already present in `precomputed`.
    BatchMulHeterogeneous {
        precomputed: Vec<Option<(ShareType, ShareData)>>,
        groups: Vec<TypedSharePairBatch>,
    },
    Open {
        share_type: ShareType,
        share_data: ShareData,
    },
    BatchOpen {
        share_type: ShareType,
        share_data: Vec<ShareData>,
    },
    /// A compiler-fused open split into homogeneous runtime-type partitions.
    BatchOpenHeterogeneous {
        output_len: usize,
        groups: Vec<TypedShareBatch>,
    },
    SendToClient {
        share_data: Vec<ShareData>,
        encode_share_list: bool,
        client_id: ClientId,
        output_share_count: ClientOutputShareCount,
    },
    OpenExp {
        group: MpcExponentGroup,
        share_type: ShareType,
        share_data: ShareData,
        generator_bytes: Vec<u8>,
    },
    Random {
        share_type: ShareType,
    },
    RandomInt {
        share_type: ShareType,
    },
    OpenField {
        share_type: ShareType,
        share_data: ShareData,
    },
    OpenExpCustom {
        share_type: ShareType,
        share_data: ShareData,
        generator_bytes: Vec<u8>,
    },
    RbcBroadcast {
        message: Vec<u8>,
    },
    RbcReceive {
        from_party: MpcPartyId,
        timeout_ms: u64,
    },
    RbcReceiveAny {
        timeout_ms: u64,
    },
}

#[derive(Debug)]
pub(super) struct CompletedMpcBuiltinCall {
    return_register: RuntimeRegister,
    call_target: HookCallTarget,
    result: CompletedMpcBuiltinResult,
}

#[derive(Debug)]
pub(super) enum CompletedMpcBuiltinResult {
    Value(Value),
    ShareObject {
        share_type: ShareType,
        share_data: ShareData,
    },
    ShareValue {
        share_type: ShareType,
        share_data: ShareData,
    },
    ShareValues {
        share_type: ShareType,
        share_data: Vec<ShareData>,
    },
    /// Already typed VM values in compiler-visible batch order. Used when a
    /// legal fused batch contains more than one runtime share type.
    Values(Vec<Value>),
    BatchOpen {
        share_type: ShareType,
        values: Vec<ClearShareValue>,
    },
    ByteArray(Vec<u8>),
    RbcReceiveAny {
        party_id: MpcPartyId,
        message: Vec<u8>,
    },
}

impl PendingMpcOperation {
    fn input_share(dest: RuntimeRegister, value: &Value) -> VmResult<Option<PendingMpcOperation>> {
        match value {
            Value::Share(_, _) | Value::Unit => Ok(None),
            clear => {
                let clear = clear_share_input(clear, None).map_err(|err| {
                    VmError::ClearValueInSecretRegister {
                        value_type: value.type_name(),
                        register: dest.index(),
                        reason: err.to_string(),
                    }
                })?;
                Ok(Some(PendingMpcOperation::Input { clear, dest }))
            }
        }
    }

    fn open_share(
        src: RuntimeRegister,
        dest: RuntimeRegister,
        value: Value,
    ) -> Option<PendingMpcOperation> {
        match value {
            Value::Share(share_type, share_data) => Some(PendingMpcOperation::Open {
                share_type,
                share_data,
                src,
                dest,
            }),
            _ => None,
        }
    }

    fn multiply_share(
        dest: RuntimeRegister,
        left: Value,
        right: Value,
    ) -> VmResult<Option<PendingMpcOperation>> {
        let Some(pair) = matching_share_pair("MUL", &left, &right)? else {
            return Ok(None);
        };

        ensure_matching_share_data_format("async_multiply_share", pair.left_data, pair.right_data)?;
        Ok(Some(PendingMpcOperation::Multiply {
            share_type: pair.share_type,
            left_data: pair.left_data.clone(),
            right_data: pair.right_data.clone(),
            dest,
        }))
    }

    fn boolean_bit_share(
        op: RuntimeBinaryOp,
        dest: RuntimeRegister,
        left: Value,
        right: Value,
    ) -> VmResult<Option<PendingMpcOperation>> {
        let operation = match op {
            RuntimeBinaryOp::BitAnd => "AND",
            RuntimeBinaryOp::BitOr => "OR",
            RuntimeBinaryOp::BitXor => "XOR",
            _ => return Ok(None),
        };
        let Some(pair) = matching_share_pair(operation, &left, &right)? else {
            return Ok(None);
        };

        if pair.share_type != ShareType::boolean() {
            return Ok(None);
        }

        ensure_matching_share_data_format(
            "async_boolean_bit_share",
            pair.left_data,
            pair.right_data,
        )?;
        Ok(Some(PendingMpcOperation::BooleanBit {
            op,
            share_type: pair.share_type,
            left_data: pair.left_data.clone(),
            right_data: pair.right_data.clone(),
            dest,
        }))
    }

    pub(super) async fn execute_async<E: AsyncMpcEngine + ?Sized>(
        self,
        engine: &E,
    ) -> VmResult<CompletedMpcOperation> {
        self.ensure_engine_can_execute(engine)?;

        match self {
            PendingMpcOperation::Input { clear, dest } => {
                let share_type = clear.share_type();
                let share_data = ShareData::public(clear);

                Ok(CompletedMpcOperation::Input {
                    share_type,
                    share_data,
                    dest,
                })
            }
            PendingMpcOperation::Multiply {
                share_type,
                left_data,
                right_data,
                dest,
            } => {
                let share_data =
                    defer_multiply_share(engine, share_type, left_data, right_data).await?;

                Ok(CompletedMpcOperation::Multiply {
                    share_type,
                    share_data,
                    dest,
                })
            }
            PendingMpcOperation::BooleanBit {
                op,
                share_type,
                left_data,
                right_data,
                dest,
            } => {
                let direct_result = public_boolean_result(
                    op,
                    share_type,
                    left_data.public_input(),
                    right_data.public_input(),
                );
                let product_data =
                    defer_multiply_share(engine, share_type, left_data.clone(), right_data.clone())
                        .await?;

                Ok(CompletedMpcOperation::BooleanBit {
                    op,
                    share_type,
                    left_data,
                    right_data,
                    product_data,
                    direct_result,
                    dest,
                })
            }
            PendingMpcOperation::Open {
                share_type,
                share_data,
                src,
                dest,
            } => {
                let value = open_share_or_public_async(engine, share_type, share_data).await?;

                Ok(CompletedMpcOperation::Open {
                    share_type,
                    value,
                    src,
                    dest,
                })
            }
            PendingMpcOperation::BuiltinCall(call) => Ok(CompletedMpcOperation::BuiltinCall(
                call.execute_async(engine).await?,
            )),
        }
    }

    pub(super) fn ensure_engine_can_execute<E: AsyncMpcEngine + ?Sized>(
        &self,
        engine: &E,
    ) -> VmResult<()> {
        if !engine.is_ready() {
            return Err(VmError::MpcEngineNotReady);
        }

        match self {
            PendingMpcOperation::Input { .. } => {}
            PendingMpcOperation::Multiply {
                share_type,
                left_data,
                right_data,
                ..
            }
            | PendingMpcOperation::BooleanBit {
                share_type,
                left_data,
                right_data,
                ..
            } => {
                if multiplication_requires_protocol(*share_type, left_data, right_data) {
                    engine
                        .multiplication_ops()
                        .map_mpc_backend_err("multiplication_ops")?;
                }
            }
            PendingMpcOperation::Open { .. } => {}
            PendingMpcOperation::BuiltinCall(call) => call.ensure_engine_can_execute(engine)?,
        }

        Ok(())
    }
}

impl PendingMpcBuiltinCall {
    async fn execute_async<E: AsyncMpcEngine + ?Sized>(
        self,
        engine: &E,
    ) -> VmResult<CompletedMpcBuiltinCall> {
        let result = match self.operation {
            PendingMpcBuiltinOperation::InputShare { clear } => {
                let share_type = clear.share_type();
                let share_data = ShareData::public(clear);
                CompletedMpcBuiltinResult::ShareObject {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::Mul {
                share_type,
                left_data,
                right_data,
            } => {
                let share_data =
                    defer_multiply_share(engine, share_type, left_data, right_data).await?;
                CompletedMpcBuiltinResult::ShareValue {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::BatchMul {
                share_type,
                left_data,
                right_data,
            } => {
                let mut share_data = Vec::with_capacity(left_data.len());
                for (left, right) in left_data.into_iter().zip(right_data) {
                    share_data.push(defer_multiply_share(engine, share_type, left, right).await?);
                }
                CompletedMpcBuiltinResult::ShareValues {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::LocalShare {
                share_type,
                share_data,
            } => CompletedMpcBuiltinResult::ShareObject {
                share_type,
                share_data,
            },
            PendingMpcBuiltinOperation::BatchMulMixed {
                share_type,
                precomputed,
                left_data,
                right_data,
            } => {
                let mut deferred = Vec::with_capacity(left_data.len());
                for (left, right) in left_data.into_iter().zip(right_data) {
                    deferred.push(defer_multiply_share(engine, share_type, left, right).await?);
                }
                let mut deferred = deferred.into_iter();
                let mut share_data = Vec::with_capacity(precomputed.len());
                for slot in precomputed {
                    match slot {
                        Some(data) => share_data.push(data),
                        None => share_data.push(deferred.next().ok_or_else(|| {
                            VmError::ForeignFunction(ForeignFunctionError::CallbackFailed {
                                function: "Share.batch_mul".to_owned(),
                                source: "batch plan contains fewer products than output slots"
                                    .into(),
                            })
                        })?),
                    }
                }
                CompletedMpcBuiltinResult::ShareValues {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::BatchMulHeterogeneous {
                mut precomputed,
                groups,
            } => {
                for group in groups {
                    debug_assert_eq!(group.output_indices.len(), group.left_data.len());
                    debug_assert_eq!(group.left_data.len(), group.right_data.len());
                    let mut results = Vec::with_capacity(group.left_data.len());
                    for (left, right) in group.left_data.into_iter().zip(group.right_data) {
                        results.push(
                            defer_multiply_share(engine, group.share_type, left, right).await?,
                        );
                    }
                    if results.len() != group.output_indices.len() {
                        return Err(VmError::ForeignFunction(
                            ForeignFunctionError::CallbackFailed {
                                function: "Share.batch_mul".to_owned(),
                                source: format!(
                                    "engine returned {} products for {} batch lanes",
                                    results.len(),
                                    group.output_indices.len()
                                )
                                .into(),
                            },
                        ));
                    }
                    for (index, share_data) in
                        group.output_indices.into_iter().zip(results.into_iter())
                    {
                        precomputed[index] = Some((group.share_type, share_data));
                    }
                }
                let values = precomputed
                    .into_iter()
                    .enumerate()
                    .map(|(index, slot)| {
                        slot.map(|(share_type, share_data)| Value::Share(share_type, share_data))
                            .ok_or_else(|| {
                                VmError::ForeignFunction(ForeignFunctionError::CallbackFailed {
                                    function: "Share.batch_mul".to_owned(),
                                    source: format!("batch result lane {index} was not produced")
                                        .into(),
                                })
                            })
                    })
                    .collect::<VmResult<Vec<_>>>()?;
                CompletedMpcBuiltinResult::Values(values)
            }
            PendingMpcBuiltinOperation::Open {
                share_type,
                share_data,
            } => {
                let value = open_share_or_public_async(engine, share_type, share_data).await?;
                CompletedMpcBuiltinResult::Value(clear_share_value_to_vm_value(share_type, value))
            }
            PendingMpcBuiltinOperation::BatchOpen {
                share_type,
                share_data,
            } => {
                let values =
                    batch_open_shares_or_public_async(engine, share_type, share_data).await?;
                CompletedMpcBuiltinResult::BatchOpen { share_type, values }
            }
            PendingMpcBuiltinOperation::BatchOpenHeterogeneous { output_len, groups } => {
                let mut output = vec![None; output_len];
                let roots: Vec<_> = groups
                    .iter()
                    .flat_map(|group| group.share_data.iter())
                    .filter(|share| share.public_input().is_none())
                    .cloned()
                    .collect();
                let mut resolved = resolve_deferred_shares(engine, &roots).await?.into_iter();
                for group in groups {
                    debug_assert_eq!(group.output_indices.len(), group.share_data.len());
                    let group_shares: Vec<_> = group
                        .share_data
                        .into_iter()
                        .map(|share| {
                            if share.public_input().is_some() {
                                share
                            } else {
                                resolved
                                    .next()
                                    .expect("resolved heterogeneous batch preserves root count")
                            }
                        })
                        .collect();
                    let values = batch_open_materialized_or_public_async(
                        engine,
                        group.share_type,
                        group_shares,
                    )
                    .await?;
                    if values.len() != group.output_indices.len() {
                        return Err(VmError::ForeignFunction(
                            ForeignFunctionError::CallbackFailed {
                                function: "Share.batch_open".to_owned(),
                                source: format!(
                                    "engine returned {} values for {} batch lanes",
                                    values.len(),
                                    group.output_indices.len()
                                )
                                .into(),
                            },
                        ));
                    }
                    for (index, value) in group.output_indices.into_iter().zip(values.into_iter()) {
                        output[index] =
                            Some(clear_share_value_to_vm_value(group.share_type, value));
                    }
                }
                let values = output
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        value.ok_or_else(|| {
                            VmError::ForeignFunction(ForeignFunctionError::CallbackFailed {
                                function: "Share.batch_open".to_owned(),
                                source: format!("batch result lane {index} was not produced")
                                    .into(),
                            })
                        })
                    })
                    .collect::<VmResult<Vec<_>>>()?;
                CompletedMpcBuiltinResult::Values(values)
            }
            PendingMpcBuiltinOperation::SendToClient {
                client_id,
                share_data,
                encode_share_list,
                output_share_count,
            } => {
                let share_data = resolve_deferred_shares(engine, &share_data).await?;
                let share_bytes = if encode_share_list {
                    encode_output_share_list(&share_data).map_err(VmError::from)?
                } else {
                    share_data
                        .first()
                        .expect("one output share is present")
                        .as_bytes()
                        .to_vec()
                };
                engine
                    .send_output_to_client_async(client_id, &share_bytes, output_share_count)
                    .await
                    .map_mpc_backend_err("async_send_output_to_client")?;
                CompletedMpcBuiltinResult::Value(Value::Bool(true))
            }
            PendingMpcBuiltinOperation::OpenExp {
                group,
                share_type,
                share_data,
                generator_bytes,
            } => {
                let share_data = resolve_one_deferred_share(engine, share_data).await?;
                let bytes = engine
                    .open_share_in_exp_group_async(
                        group,
                        share_type,
                        share_data.as_bytes(),
                        &generator_bytes,
                    )
                    .await
                    .map_mpc_backend_err("async_open_share_in_exp_group")?;
                CompletedMpcBuiltinResult::ByteArray(bytes)
            }
            PendingMpcBuiltinOperation::Random { share_type } => {
                let share_data = engine
                    .random_share_async(share_type)
                    .await
                    .map_mpc_backend_err("async_random_share")?;
                CompletedMpcBuiltinResult::ShareObject {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::RandomInt { share_type } => {
                let share_data = engine
                    .random_integer_share_async(share_type)
                    .await
                    .map_mpc_backend_err("async_random_integer_share")?;
                CompletedMpcBuiltinResult::ShareValue {
                    share_type,
                    share_data,
                }
            }
            PendingMpcBuiltinOperation::OpenField {
                share_type,
                share_data,
            } => {
                let share_data = resolve_one_deferred_share(engine, share_data).await?;
                let bytes = engine
                    .open_share_as_field_async(share_type, share_data.as_bytes())
                    .await
                    .map_mpc_backend_err("async_open_share_as_field")?;
                CompletedMpcBuiltinResult::ByteArray(bytes)
            }
            PendingMpcBuiltinOperation::OpenExpCustom {
                share_type,
                share_data,
                generator_bytes,
            } => {
                let share_data = resolve_one_deferred_share(engine, share_data).await?;
                let bytes = engine
                    .open_share_in_exp_async(share_type, share_data.as_bytes(), &generator_bytes)
                    .await
                    .map_mpc_backend_err("async_open_share_in_exp")?;
                CompletedMpcBuiltinResult::ByteArray(bytes)
            }
            PendingMpcBuiltinOperation::RbcBroadcast { message } => {
                let session_id = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .rbc_broadcast_async(&message)
                    .await
                    .map_mpc_backend_err("async_rbc_broadcast")?;
                CompletedMpcBuiltinResult::Value(session_id_value(session_id.id())?)
            }
            PendingMpcBuiltinOperation::RbcReceive {
                from_party,
                timeout_ms,
            } => {
                let message = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .rbc_receive_async(from_party, timeout_ms)
                    .await
                    .map_mpc_backend_err("async_rbc_receive")?;
                CompletedMpcBuiltinResult::Value(Value::String(consensus_message_to_string(
                    message,
                    "<binary data>",
                )))
            }
            PendingMpcBuiltinOperation::RbcReceiveAny { timeout_ms } => {
                let (party_id, message) = engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?
                    .rbc_receive_any_async(timeout_ms)
                    .await
                    .map_mpc_backend_err("async_rbc_receive_any")?;
                CompletedMpcBuiltinResult::RbcReceiveAny { party_id, message }
            }
        };

        Ok(CompletedMpcBuiltinCall {
            return_register: self.return_register,
            call_target: self.call_target,
            result,
        })
    }

    fn ensure_engine_can_execute<E: AsyncMpcEngine + ?Sized>(&self, engine: &E) -> VmResult<()> {
        match &self.operation {
            PendingMpcBuiltinOperation::InputShare { .. } => {}
            PendingMpcBuiltinOperation::LocalShare { .. } => {}
            PendingMpcBuiltinOperation::Mul {
                share_type,
                left_data,
                right_data,
            } => {
                if multiplication_requires_protocol(*share_type, left_data, right_data) {
                    engine
                        .multiplication_ops()
                        .map_mpc_backend_err("multiplication_ops")?;
                }
            }
            PendingMpcBuiltinOperation::BatchMul {
                share_type,
                left_data,
                right_data,
            } => {
                if left_data
                    .iter()
                    .zip(right_data)
                    .any(|(left, right)| multiplication_requires_protocol(*share_type, left, right))
                {
                    engine
                        .multiplication_ops()
                        .map_mpc_backend_err("multiplication_ops")?;
                }
            }
            PendingMpcBuiltinOperation::BatchMulMixed {
                share_type,
                left_data,
                right_data,
                ..
            } => {
                if left_data
                    .iter()
                    .zip(right_data)
                    .any(|(left, right)| multiplication_requires_protocol(*share_type, left, right))
                {
                    engine
                        .multiplication_ops()
                        .map_mpc_backend_err("multiplication_ops")?;
                }
            }
            PendingMpcBuiltinOperation::BatchMulHeterogeneous { groups, .. } => {
                if groups.iter().any(|group| {
                    group
                        .left_data
                        .iter()
                        .zip(&group.right_data)
                        .any(|(left, right)| {
                            multiplication_requires_protocol(group.share_type, left, right)
                        })
                }) {
                    engine
                        .multiplication_ops()
                        .map_mpc_backend_err("multiplication_ops")?;
                }
            }
            PendingMpcBuiltinOperation::Open { .. }
            | PendingMpcBuiltinOperation::BatchOpen { .. }
            | PendingMpcBuiltinOperation::BatchOpenHeterogeneous { .. } => {}
            PendingMpcBuiltinOperation::SendToClient { .. } => {
                engine
                    .client_output_ops()
                    .map_mpc_backend_err("client_output_ops")?;
            }
            PendingMpcBuiltinOperation::OpenExp { .. }
            | PendingMpcBuiltinOperation::OpenExpCustom { .. } => {
                engine
                    .open_in_exp_ops()
                    .map_mpc_backend_err("open_in_exp_ops")?;
            }
            PendingMpcBuiltinOperation::Random { .. } => {
                engine
                    .randomness_ops()
                    .map_mpc_backend_err("randomness_ops")?;
            }
            PendingMpcBuiltinOperation::RandomInt { .. } => {
                engine
                    .randomness_ops()
                    .map_mpc_backend_err("randomness_ops")?;
            }
            PendingMpcBuiltinOperation::OpenField { .. } => {
                engine
                    .field_open_ops()
                    .map_mpc_backend_err("field_open_ops")?;
            }
            PendingMpcBuiltinOperation::RbcBroadcast { .. }
            | PendingMpcBuiltinOperation::RbcReceive { .. }
            | PendingMpcBuiltinOperation::RbcReceiveAny { .. } => {
                engine
                    .async_consensus_ops()
                    .map_mpc_backend_err("async_consensus_ops")?;
            }
        }

        Ok(())
    }
}

fn public_boolean_result(
    op: RuntimeBinaryOp,
    share_type: ShareType,
    left: Option<ClearShareInput>,
    right: Option<ClearShareInput>,
) -> Option<ShareData> {
    if share_type != ShareType::boolean() {
        return None;
    }
    let (Some(left), Some(right)) = (left, right) else {
        return None;
    };
    let (ClearShareValue::Boolean(left), ClearShareValue::Boolean(right)) =
        (left.value(), right.value())
    else {
        return None;
    };
    let value = match op {
        RuntimeBinaryOp::BitAnd => left & right,
        RuntimeBinaryOp::BitOr => left | right,
        RuntimeBinaryOp::BitXor => left ^ right,
        _ => return None,
    };
    Some(ShareData::public(ClearShareInput::new(
        share_type,
        ClearShareValue::Boolean(value),
    )))
}

async fn open_share_or_public_async<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    share_type: ShareType,
    share_data: ShareData,
) -> VmResult<ClearShareValue> {
    if let Some(public) = share_data.public_input() {
        if public.share_type() != share_type {
            return Err(VmError::Message(format!(
                "public share type mismatch: expected {share_type:?}, got {:?}",
                public.share_type()
            )));
        }
        return Ok(public.value());
    }
    let share_data = resolve_one_deferred_share(engine, share_data).await?;
    engine
        .open_share_async(share_type, share_data.as_bytes())
        .await
        .map_mpc_backend_err("async_open_share")
}

async fn batch_open_shares_or_public_async<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    share_type: ShareType,
    shares: Vec<ShareData>,
) -> VmResult<Vec<ClearShareValue>> {
    let secret_roots: Vec<_> = shares
        .iter()
        .filter(|share| share.public_input().is_none())
        .cloned()
        .collect();
    let mut resolved = resolve_deferred_shares(engine, &secret_roots)
        .await?
        .into_iter();
    let shares = shares
        .into_iter()
        .map(|share| {
            if share.public_input().is_some() {
                share
            } else {
                resolved
                    .next()
                    .expect("resolved batch preserves non-public root count")
            }
        })
        .collect();
    batch_open_materialized_or_public_async(engine, share_type, shares).await
}

async fn batch_open_materialized_or_public_async<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    share_type: ShareType,
    shares: Vec<ShareData>,
) -> VmResult<Vec<ClearShareValue>> {
    let mut output = vec![None; shares.len()];
    let mut secret_indices = Vec::new();
    let mut secret_bytes = Vec::new();
    for (index, share) in shares.into_iter().enumerate() {
        if let Some(public) = share.public_input() {
            if public.share_type() != share_type {
                return Err(VmError::Message(format!(
                    "public share type mismatch in batch lane {index}: expected {share_type:?}, got {:?}",
                    public.share_type()
                )));
            }
            output[index] = Some(public.value());
        } else {
            secret_indices.push(index);
            secret_bytes.push(share.into_bytes());
        }
    }

    if !secret_bytes.is_empty() {
        let values = engine
            .batch_open_shares_async(share_type, &secret_bytes)
            .await
            .map_mpc_backend_err("async_batch_open_shares")?;
        if values.len() != secret_indices.len() {
            return Err(VmError::Message(format!(
                "MPC backend returned {} openings for a batch of {}",
                values.len(),
                secret_indices.len()
            )));
        }
        for (index, value) in secret_indices.into_iter().zip(values) {
            output[index] = Some(value);
        }
    }

    output
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            value.ok_or_else(|| {
                VmError::Message(format!("batch opening did not produce lane {index}"))
            })
        })
        .collect()
}

async fn resolve_one_deferred_share<E: AsyncMpcEngine + ?Sized>(
    engine: &E,
    share_data: ShareData,
) -> VmResult<ShareData> {
    resolve_deferred_shares(engine, std::slice::from_ref(&share_data))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| VmError::Message("deferred share resolver returned no value".to_owned()))
}

fn session_id_value(session_id: u64) -> VmResult<Value> {
    Ok(Value::I64(
        u64_to_vm_i64(session_id, "session_id")
            .map_err(|error| VmError::from(error.to_string()))?,
    ))
}

fn consensus_message_to_string(message: Vec<u8>, binary_fallback: &str) -> String {
    String::from_utf8(message).unwrap_or_else(|_| binary_fallback.to_string())
}

impl VMState {
    pub(super) fn plan_async_mpc_operation_for_fetched(
        &mut self,
        fetched: FetchedInstruction<'_>,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>> {
        match fetched.runtime_instruction() {
            RuntimeInstruction::LoadImmediate { dest, value } => {
                if !self
                    .current_register_layout()?
                    .is_secret(dest.register_index())
                {
                    return Ok(None);
                }

                PendingMpcOperation::input_share(dest, fetched.load_immediate_value(&value)?)
            }
            RuntimeInstruction::Call { function } => self
                .plan_async_mpc_builtin_call(fetched.call_target_name(&function)?, hooks_enabled),
            instruction => self.plan_async_mpc_operation(&instruction, hooks_enabled),
        }
    }

    pub(super) fn plan_async_mpc_operation(
        &mut self,
        instruction: &RuntimeInstruction,
        hooks_enabled: bool,
    ) -> VmResult<Option<PendingMpcOperation>> {
        match instruction {
            RuntimeInstruction::LoadImmediate { dest, value } => {
                if !self
                    .current_register_layout()?
                    .is_secret(dest.register_index())
                {
                    return Ok(None);
                }

                PendingMpcOperation::input_share(*dest, value.direct_value()?)
            }
            RuntimeInstruction::Move { dest, src } => {
                if self
                    .current_register_layout()?
                    .move_kind(dest.register_index(), src.register_index())
                    != RegisterMoveKind::SecretToClear
                {
                    return Ok(None);
                }

                let src_value = self.resolve_register(*src)?.into_value();
                Ok(PendingMpcOperation::open_share(*src, *dest, src_value))
            }
            RuntimeInstruction::Binary {
                op: RuntimeBinaryOp::Multiply,
                dest,
                lhs,
                rhs,
            } => {
                let (left, right) = self.resolve_register_pair(*lhs, *rhs)?.into_values();
                PendingMpcOperation::multiply_share(*dest, left, right)
            }
            RuntimeInstruction::Binary {
                op:
                    op @ (RuntimeBinaryOp::BitAnd | RuntimeBinaryOp::BitOr | RuntimeBinaryOp::BitXor),
                dest,
                lhs,
                rhs,
            } => {
                let (left, right) = self.resolve_register_pair(*lhs, *rhs)?.into_values();
                PendingMpcOperation::boolean_bit_share(*op, *dest, left, right)
            }
            RuntimeInstruction::Call { function } => {
                self.plan_async_mpc_builtin_call(function.direct_function_name()?, hooks_enabled)
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn ensure_async_engine_matches<E: MpcEngine + ?Sized>(
        &self,
        engine: &E,
    ) -> VmResult<()> {
        let configured = self.mpc_runtime.configured_engine()?;

        let configured_identity = configured.identity();
        let async_identity = engine.identity();

        if configured_identity != async_identity {
            return Err(VmError::AsyncMpcEngineMismatch {
                runtime: Box::new(async_identity),
                configured: Box::new(configured_identity),
            });
        }

        Ok(())
    }

    pub(crate) fn apply_completed_vm_effect(&mut self, effect: CompletedVmEffect) -> VmResult<()> {
        let (operation, after_instruction, hooks_enabled) = effect.into_parts();
        self.apply_completed_mpc_operation(operation, hooks_enabled)?;

        if let Some(after_instruction) = after_instruction {
            let event = HookEvent::AfterInstructionExecute(after_instruction);
            self.trigger_hook_with_snapshot(&event)?;
        } else {
            debug_assert!(!hooks_enabled);
        }

        Ok(())
    }

    pub(super) fn apply_completed_mpc_operation(
        &mut self,
        operation: CompletedMpcOperation,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        match operation {
            CompletedMpcOperation::Input {
                share_type,
                share_data,
                dest,
            } => {
                self.write_current_register(
                    dest,
                    Value::Share(share_type, share_data),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::Multiply {
                share_type,
                share_data,
                dest,
            } => {
                self.write_current_register(
                    dest,
                    Value::Share(share_type, share_data),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::BooleanBit {
                op,
                share_type,
                left_data,
                right_data,
                product_data,
                direct_result,
                dest,
            } => {
                let share_runtime = || self.share_runtime().map_err(Into::into);
                let share_data = if let Some(direct_result) = direct_result {
                    direct_result
                } else {
                    match op {
                        RuntimeBinaryOp::BitAnd => product_data,
                        RuntimeBinaryOp::BitOr => bool_or_data(
                            &share_runtime,
                            share_type,
                            &left_data,
                            &right_data,
                            &product_data,
                        )?,
                        RuntimeBinaryOp::BitXor => bool_xor_data(
                            &share_runtime,
                            share_type,
                            &left_data,
                            &right_data,
                            &product_data,
                        )?,
                        _ => {
                            return Err(VmError::Message(
                                "completed boolean bit operation used a non-bitwise opcode"
                                    .to_string(),
                            ))
                        }
                    }
                };
                self.write_current_register(
                    dest,
                    Value::Share(share_type, share_data),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::Open {
                share_type,
                value,
                src,
                dest,
            } => {
                self.write_mov_result(
                    dest,
                    src,
                    clear_share_value_to_vm_value(share_type, value),
                    hooks_enabled,
                )?;
                Ok(())
            }
            CompletedMpcOperation::BuiltinCall(call) => {
                let result = self.materialize_mpc_builtin_result(call.result)?;
                self.complete_foreign_function_return(
                    call.return_register,
                    call.call_target,
                    result,
                    hooks_enabled,
                )
            }
        }
    }

    fn materialize_mpc_builtin_result(
        &mut self,
        result: CompletedMpcBuiltinResult,
    ) -> VmResult<Value> {
        match result {
            CompletedMpcBuiltinResult::Value(value) => Ok(value),
            CompletedMpcBuiltinResult::ShareObject {
                share_type,
                share_data,
            } => {
                let party_id = self
                    .mpc_runtime_info()
                    .ok_or(VmError::MpcEngineNotConfigured)?
                    .party()
                    .id();
                self.create_share_object_value(share_type, share_data, party_id)
            }
            CompletedMpcBuiltinResult::ShareValue {
                share_type,
                share_data,
            } => Ok(Value::Share(share_type, share_data)),
            CompletedMpcBuiltinResult::ShareValues {
                share_type,
                share_data,
            } => {
                let shares: Vec<Value> = share_data
                    .into_iter()
                    .map(|share_data| Value::Share(share_type, share_data))
                    .collect();
                let result_ref = self.create_array_ref(shares.len())?;
                self.push_array_ref_values(result_ref, &shares)?;
                Ok(Value::from(result_ref))
            }
            CompletedMpcBuiltinResult::Values(values) => {
                let result_ref = self.create_array_ref(values.len())?;
                self.push_array_ref_values(result_ref, &values)?;
                Ok(Value::from(result_ref))
            }
            CompletedMpcBuiltinResult::BatchOpen { share_type, values } => {
                let revealed: Vec<Value> = values
                    .into_iter()
                    .map(|value| clear_share_value_to_vm_value(share_type, value))
                    .collect();
                let result_ref = self.create_array_ref(revealed.len())?;
                self.push_array_ref_values(result_ref, &revealed)?;
                Ok(Value::from(result_ref))
            }
            CompletedMpcBuiltinResult::ByteArray(bytes) => self.create_byte_array(&bytes),
            CompletedMpcBuiltinResult::RbcReceiveAny { party_id, message } => {
                let object_ref = self.create_object_ref()?;
                let table_ref = TableRef::from(object_ref);
                for (key, value) in [
                    (
                        Value::String("party_id".to_string()),
                        Value::I64(
                            usize_to_vm_i64(party_id.id(), "party_id")
                                .map_err(|error| VmError::from(error.to_string()))?,
                        ),
                    ),
                    (
                        Value::String("message".to_string()),
                        Value::String(consensus_message_to_string(message, "<binary>")),
                    ),
                ] {
                    self.set_table_field(table_ref, key, value)?;
                }
                Ok(Value::from(object_ref))
            }
        }
    }
}
