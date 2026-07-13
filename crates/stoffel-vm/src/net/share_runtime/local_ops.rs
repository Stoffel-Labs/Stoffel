use super::format::{ensure_homogeneous_share_data_format, ensure_matching_share_data_format};
use super::MpcShareRuntime;
use crate::error::{MpcBackendResultExt, VmResult};
use crate::net::share_algebra;
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, DeferredShareOperation, ShareData, ShareType, Value,
};

#[derive(Clone, Copy)]
enum PublicBinaryOperation {
    Add,
    Sub,
    Multiply,
}

fn public_scalar(input: ClearShareInput) -> Option<i64> {
    match input.value() {
        ClearShareValue::Integer(value) => Some(value),
        ClearShareValue::UnsignedInteger(value) => i64::try_from(value).ok(),
        ClearShareValue::Boolean(value) => Some(i64::from(value)),
        ClearShareValue::FixedPoint(_) => None,
    }
}

fn checked_i64_binary(left: i64, right: i64, operation: PublicBinaryOperation) -> Option<i64> {
    match operation {
        PublicBinaryOperation::Add => left.checked_add(right),
        PublicBinaryOperation::Sub => left.checked_sub(right),
        PublicBinaryOperation::Multiply => left.checked_mul(right),
    }
}

fn checked_u64_binary(left: u64, right: u64, operation: PublicBinaryOperation) -> Option<u64> {
    match operation {
        PublicBinaryOperation::Add => left.checked_add(right),
        PublicBinaryOperation::Sub => left.checked_sub(right),
        PublicBinaryOperation::Multiply => left.checked_mul(right),
    }
}

fn public_bool_result(ty: ShareType, value: i64) -> Option<ShareData> {
    if ty != ShareType::boolean() {
        return None;
    }
    let value = match value {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(ShareData::public(ClearShareInput::new(
        ty,
        ClearShareValue::Boolean(value),
    )))
}

fn public_binary_result(
    ty: ShareType,
    left: ClearShareInput,
    right: ClearShareInput,
    operation: PublicBinaryOperation,
) -> Option<ShareData> {
    if left.share_type() != ty || right.share_type() != ty {
        return None;
    }
    match (left.value(), right.value()) {
        (ClearShareValue::Integer(left), ClearShareValue::Integer(right)) => {
            if ty == ShareType::boolean() {
                return None;
            }
            let value = checked_i64_binary(left, right, operation)?;
            Some(ShareData::public(ClearShareInput::new(
                ty,
                ClearShareValue::Integer(value),
            )))
        }
        (ClearShareValue::Boolean(left), ClearShareValue::Boolean(right)) => {
            let value = checked_i64_binary(i64::from(left), i64::from(right), operation)?;
            public_bool_result(ty, value)
        }
        (ClearShareValue::UnsignedInteger(left), ClearShareValue::UnsignedInteger(right)) => {
            let value = checked_u64_binary(left, right, operation)?;
            Some(ShareData::public(ClearShareInput::new(
                ty,
                ClearShareValue::UnsignedInteger(value),
            )))
        }
        _ => None,
    }
}

fn public_unary_scalar_result(
    ty: ShareType,
    input: ClearShareInput,
    scalar: i64,
    operation: PublicBinaryOperation,
) -> Option<ShareData> {
    if input.share_type() != ty {
        return None;
    }
    let value = match input.value() {
        ClearShareValue::Integer(value) if ty != ShareType::boolean() => {
            ClearShareValue::Integer(checked_i64_binary(value, scalar, operation)?)
        }
        ClearShareValue::UnsignedInteger(value) => {
            let scalar = u64::try_from(scalar).ok()?;
            ClearShareValue::UnsignedInteger(checked_u64_binary(value, scalar, operation)?)
        }
        ClearShareValue::Boolean(value) => {
            let result = checked_i64_binary(i64::from(value), scalar, operation)?;
            return public_bool_result(ty, result);
        }
        ClearShareValue::Integer(_) | ClearShareValue::FixedPoint(_) => return None,
    };
    Some(ShareData::public(ClearShareInput::new(ty, value)))
}

fn public_scalar_left_result(
    ty: ShareType,
    scalar: i64,
    input: ClearShareInput,
    operation: PublicBinaryOperation,
) -> Option<ShareData> {
    if input.share_type() != ty {
        return None;
    }
    let value = match input.value() {
        ClearShareValue::Integer(value) if ty != ShareType::boolean() => {
            ClearShareValue::Integer(checked_i64_binary(scalar, value, operation)?)
        }
        ClearShareValue::UnsignedInteger(value) => {
            let scalar = u64::try_from(scalar).ok()?;
            ClearShareValue::UnsignedInteger(checked_u64_binary(scalar, value, operation)?)
        }
        ClearShareValue::Boolean(value) => {
            let result = checked_i64_binary(scalar, i64::from(value), operation)?;
            return public_bool_result(ty, result);
        }
        ClearShareValue::Integer(_) | ClearShareValue::FixedPoint(_) => return None,
    };
    Some(ShareData::public(ClearShareInput::new(ty, value)))
}

impl MpcShareRuntime<'_> {
    pub(crate) fn multiply_share_data(
        &self,
        share_type: ShareType,
        left_data: &ShareData,
        right_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.ensure_ready()?;
        if let (Some(left), Some(right)) = (left_data.public_input(), right_data.public_input()) {
            if let Some(result) =
                public_binary_result(share_type, left, right, PublicBinaryOperation::Multiply)
            {
                return Ok(result);
            }
        }
        if let Some(left) = left_data.public_input().and_then(public_scalar) {
            return self.mul_scalar_data(share_type, right_data, left);
        }
        if let Some(right) = right_data.public_input().and_then(public_scalar) {
            return self.mul_scalar_data(share_type, left_data, right);
        }
        let left_materialized = self.materialize_public_share(left_data)?;
        let right_materialized = self.materialize_public_share(right_data)?;
        ensure_matching_share_data_format(
            "multiply_share",
            &left_materialized,
            &right_materialized,
        )?;
        if left_materialized.is_deferred() || right_materialized.is_deferred() {
            return Err(
                "synchronous share multiplication cannot consume unresolved deferred shares".into(),
            );
        }
        self.engine
            .multiplication_ops()
            .map_mpc_backend_err("multiplication_ops")?
            .multiply_share(
                share_type,
                left_materialized.as_bytes(),
                right_materialized.as_bytes(),
            )
            .map_mpc_backend_err("multiply_share")
    }

    pub(crate) fn batch_multiply_share_data(
        &self,
        share_type: ShareType,
        left_data: &[ShareData],
        right_data: &[ShareData],
    ) -> VmResult<Vec<ShareData>> {
        self.ensure_ready()?;
        if left_data.len() != right_data.len() {
            return Err("batch multiplication requires matching input lengths".into());
        }
        let mut output = vec![None; left_data.len()];
        let mut interactive_indices = Vec::new();
        let mut pairs = Vec::new();
        for (index, (left, right)) in left_data.iter().zip(right_data).enumerate() {
            if let (Some(left_public), Some(right_public)) =
                (left.public_input(), right.public_input())
            {
                if let Some(result) = public_binary_result(
                    share_type,
                    left_public,
                    right_public,
                    PublicBinaryOperation::Multiply,
                ) {
                    output[index] = Some(result);
                    continue;
                }
            }
            if let Some(scalar) = left.public_input().and_then(public_scalar) {
                output[index] = Some(self.mul_scalar_data(share_type, right, scalar)?);
                continue;
            }
            if let Some(scalar) = right.public_input().and_then(public_scalar) {
                output[index] = Some(self.mul_scalar_data(share_type, left, scalar)?);
                continue;
            }

            let left = self.materialize_public_share(left)?;
            let right = self.materialize_public_share(right)?;
            if left.is_deferred() || right.is_deferred() {
                return Err(
                    "synchronous batch multiplication cannot consume unresolved deferred shares"
                        .into(),
                );
            }
            ensure_matching_share_data_format("batch_multiply_shares", &left, &right)?;
            interactive_indices.push(index);
            pairs.push((left.as_bytes().to_vec(), right.as_bytes().to_vec()));
        }
        let products = if pairs.is_empty() {
            Vec::new()
        } else {
            self.engine
                .multiplication_ops()
                .map_mpc_backend_err("multiplication_ops")?
                .batch_multiply_shares(share_type, &pairs)
                .map_mpc_backend_err("batch_multiply_shares")?
        };
        if products.len() != interactive_indices.len() {
            return Err(format!(
                "MPC backend returned {} products for a batch of {}",
                products.len(),
                interactive_indices.len()
            )
            .into());
        }
        for (index, product) in interactive_indices.into_iter().zip(products) {
            output[index] = Some(product);
        }
        output
            .into_iter()
            .enumerate()
            .map(|(index, product)| {
                product.ok_or_else(|| {
                    format!("batch multiplication did not produce lane {index}").into()
                })
            })
            .collect()
    }

    pub(crate) fn add_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        if let (Some(left), Some(right)) = (lhs_data.public_input(), rhs_data.public_input()) {
            if let Some(result) = public_binary_result(ty, left, right, PublicBinaryOperation::Add)
            {
                return Ok(result);
            }
        }
        if let Some(left) = lhs_data.public_input().and_then(public_scalar) {
            return self.add_scalar_data(ty, rhs_data, left);
        }
        if let Some(right) = rhs_data.public_input().and_then(public_scalar) {
            return self.add_scalar_data(ty, lhs_data, right);
        }
        let lhs_data = self.materialize_public_share(lhs_data)?;
        let rhs_data = self.materialize_public_share(rhs_data)?;
        ensure_matching_share_data_format("add_share_local", &lhs_data, &rhs_data)?;
        if lhs_data.is_deferred() || rhs_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                lhs_data.format(),
                DeferredShareOperation::Add {
                    left: lhs_data.clone(),
                    right: rhs_data.clone(),
                },
            ));
        }
        let result = self
            .engine
            .add_share_local(ty, lhs_data.as_bytes(), rhs_data.as_bytes())
            .map_mpc_backend_err("add_share_local")?;
        self.preserve_share_data_format(&lhs_data, result)
    }

    pub(crate) fn sub_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        if let (Some(left), Some(right)) = (lhs_data.public_input(), rhs_data.public_input()) {
            if let Some(result) = public_binary_result(ty, left, right, PublicBinaryOperation::Sub)
            {
                return Ok(result);
            }
        }
        if let Some(right) = rhs_data.public_input().and_then(public_scalar) {
            return self.sub_scalar_data(ty, lhs_data, right);
        }
        if let Some(left) = lhs_data.public_input().and_then(public_scalar) {
            return self.scalar_sub_data(ty, left, rhs_data);
        }
        let lhs_data = self.materialize_public_share(lhs_data)?;
        let rhs_data = self.materialize_public_share(rhs_data)?;
        ensure_matching_share_data_format("sub_share_local", &lhs_data, &rhs_data)?;
        if lhs_data.is_deferred() || rhs_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                lhs_data.format(),
                DeferredShareOperation::Sub {
                    left: lhs_data.clone(),
                    right: rhs_data.clone(),
                },
            ));
        }
        let result = self
            .engine
            .sub_share_local(ty, lhs_data.as_bytes(), rhs_data.as_bytes())
            .map_mpc_backend_err("sub_share_local")?;
        self.preserve_share_data_format(&lhs_data, result)
    }

    pub(crate) fn neg_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<ShareData> {
        if let Some(input) = share_data.public_input() {
            if let Some(result) =
                public_unary_scalar_result(ty, input, -1, PublicBinaryOperation::Multiply)
            {
                return Ok(result);
            }
        }
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::Neg {
                    share: share_data.clone(),
                },
            ));
        }
        let result = self
            .engine
            .neg_share_local(ty, share_data.as_bytes())
            .map_mpc_backend_err("neg_share_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    pub(crate) fn add_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        if let Some(input) = share_data.public_input() {
            if let Some(result) =
                public_unary_scalar_result(ty, input, scalar, PublicBinaryOperation::Add)
            {
                return Ok(result);
            }
        }
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::AddScalar {
                    share: share_data.clone(),
                    scalar,
                },
            ));
        }
        let result = self
            .engine
            .add_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("add_share_scalar_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    pub(crate) fn sub_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        if let Some(input) = share_data.public_input() {
            if let Some(result) =
                public_unary_scalar_result(ty, input, scalar, PublicBinaryOperation::Sub)
            {
                return Ok(result);
            }
        }
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::SubScalar {
                    share: share_data.clone(),
                    scalar,
                },
            ));
        }
        let result = self
            .engine
            .sub_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("sub_share_scalar_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    pub(crate) fn scalar_sub_data(
        &self,
        ty: ShareType,
        scalar: i64,
        share_data: &ShareData,
    ) -> VmResult<ShareData> {
        if let Some(input) = share_data.public_input() {
            if let Some(result) =
                public_scalar_left_result(ty, scalar, input, PublicBinaryOperation::Sub)
            {
                return Ok(result);
            }
        }
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::ScalarSub {
                    scalar,
                    share: share_data.clone(),
                },
            ));
        }
        let result = self
            .engine
            .scalar_sub_share_local(ty, scalar, share_data.as_bytes())
            .map_mpc_backend_err("scalar_sub_share_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    pub(crate) fn div_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::DivScalar {
                    share: share_data.clone(),
                    scalar,
                },
            ));
        }
        let result = self
            .engine
            .div_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("div_share_scalar_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    /// Divide a secret fixed-point share by a public positive constant using the
    /// interactive MPC division protocol. `divisor_scaled` is `round(divisor *
    /// 2^f)`. Unlike `div_scalar_data` (a local field operation), this performs a
    /// truncation round so the result is the true fixed-point quotient.
    pub(crate) fn div_fixed_by_const_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        divisor_scaled: i64,
    ) -> VmResult<ShareData> {
        self.ensure_ready()?;
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Err("fixed-point division cannot consume an unresolved deferred share".into());
        }
        self.engine
            .multiplication_ops()
            .map_mpc_backend_err("multiplication_ops")?
            .divide_fixed_by_constant(ty, share_data.as_bytes(), divisor_scaled)
            .map_mpc_backend_err("divide_fixed_by_constant")
    }

    pub(crate) fn mul_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        if let Some(input) = share_data.public_input() {
            if let Some(result) =
                public_unary_scalar_result(ty, input, scalar, PublicBinaryOperation::Multiply)
            {
                return Ok(result);
            }
        }
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::MulScalar {
                    share: share_data.clone(),
                    scalar,
                },
            ));
        }
        let result = self
            .engine
            .mul_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("mul_share_scalar_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    pub(crate) fn mul_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar_bytes: &[u8],
    ) -> VmResult<ShareData> {
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::MulField {
                    share: share_data.clone(),
                    scalar: scalar_bytes.into(),
                },
            ));
        }
        let result = self
            .engine
            .mul_share_field_local(ty, share_data.as_bytes(), scalar_bytes)
            .map_mpc_backend_err("mul_share_field_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    pub(crate) fn add_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        field_bytes: &[u8],
    ) -> VmResult<ShareData> {
        let share_data = self.materialize_public_share(share_data)?;
        if share_data.is_deferred() {
            return Ok(ShareData::deferred(
                ty,
                share_data.format(),
                DeferredShareOperation::AddField {
                    share: share_data.clone(),
                    field: field_bytes.into(),
                },
            ));
        }
        let result = self
            .engine
            .add_share_field_local(ty, share_data.as_bytes(), field_bytes)
            .map_mpc_backend_err("add_share_field_local")?;
        self.preserve_share_data_format(&share_data, result)
    }

    #[cfg(test)]
    pub(crate) fn add_bytes(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.engine
            .add_share_local(ty, lhs_bytes, rhs_bytes)
            .map_mpc_backend_err("add_share_local")
    }

    #[cfg(test)]
    pub(crate) fn add_scalar_bytes(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> VmResult<Vec<u8>> {
        self.engine
            .add_share_scalar_local(ty, share_bytes, scalar)
            .map_mpc_backend_err("add_share_scalar_local")
    }

    #[cfg(test)]
    pub(crate) fn sub_scalar_bytes(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> VmResult<Vec<u8>> {
        self.engine
            .sub_share_scalar_local(ty, share_bytes, scalar)
            .map_mpc_backend_err("sub_share_scalar_local")
    }

    #[cfg(test)]
    pub(crate) fn scalar_sub_bytes(
        &self,
        ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.engine
            .scalar_sub_share_local(ty, scalar, share_bytes)
            .map_mpc_backend_err("scalar_sub_share_local")
    }

    pub(crate) fn interpolate_share_data_local(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Value> {
        self.ensure_ready()?;
        let shares = shares
            .iter()
            .map(|share| self.materialize_public_share(share))
            .collect::<VmResult<Vec<_>>>()?;
        ensure_homogeneous_share_data_format("interpolate_shares_local", &shares)?;
        if shares.iter().any(ShareData::is_deferred) {
            return Err("local interpolation cannot consume unresolved deferred shares".into());
        }
        let share_bytes: Vec<Vec<u8>> = shares
            .iter()
            .map(|share_data| share_data.as_bytes().to_vec())
            .collect();
        self.interpolate_bytes_local(ty, &share_bytes)
    }

    fn interpolate_bytes_local(&self, ty: ShareType, shares: &[Vec<u8>]) -> VmResult<Value> {
        self.engine
            .interpolate_shares_local(ty, shares)
            .map_mpc_backend_err("interpolate_shares_local")
    }

    fn preserve_share_data_format(
        &self,
        template: &ShareData,
        result_bytes: Vec<u8>,
    ) -> VmResult<ShareData> {
        share_algebra::preserve_share_data_format_for_curve(
            self.engine.curve_config(),
            template,
            result_bytes,
        )
        .map_mpc_backend_err("preserve_share_data_format")
    }
}
