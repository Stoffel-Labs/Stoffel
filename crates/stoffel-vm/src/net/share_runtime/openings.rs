use super::format::ensure_homogeneous_share_data_format;
use super::MpcShareRuntime;
use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::net::curve::clear_share_value_to_vm_value;
use crate::net::mpc_engine::MpcExponentGroup;
use stoffel_vm_types::core_types::{ClearShareValue, ShareData, ShareType, Value};

impl MpcShareRuntime<'_> {
    pub(crate) fn open_share_value(&self, value: &Value) -> VmResult<Value> {
        match value {
            Value::Share(
                ty @ (ShareType::SecretInt { .. } | ShareType::SecretUInt { .. }),
                share_data,
            )
            | Value::Share(ty @ ShareType::SecretFixedPoint { .. }, share_data) => Ok(
                clear_share_value_to_vm_value(*ty, self.open_share_data(*ty, share_data)?),
            ),
            _ => Err(VmError::InvalidShareRevealValue),
        }
    }

    pub(crate) fn open_share_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<ClearShareValue> {
        self.ensure_ready()?;
        if let Some(public) = share_data.public_input() {
            if public.share_type() != ty {
                return Err(VmError::Message(format!(
                    "public share type mismatch: expected {ty:?}, got {:?}",
                    public.share_type()
                )));
            }
            return Ok(public.value());
        }
        self.engine
            .open_share(ty, share_data.as_bytes())
            .map_mpc_backend_err("open_share")
    }

    pub(crate) fn batch_open_share_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<ClearShareValue>> {
        self.ensure_ready()?;
        ensure_homogeneous_share_data_format("batch_open_shares", shares)?;
        let mut output = vec![None; shares.len()];
        let mut secret_indices = Vec::new();
        let mut share_bytes = Vec::new();
        for (index, share) in shares.iter().enumerate() {
            if let Some(public) = share.public_input() {
                if public.share_type() != ty {
                    return Err(VmError::Message(format!(
                        "public share type mismatch in batch lane {index}: expected {ty:?}, got {:?}",
                        public.share_type()
                    )));
                }
                output[index] = Some(public.value());
            } else {
                secret_indices.push(index);
                share_bytes.push(share.as_bytes().to_vec());
            }
        }
        if !share_bytes.is_empty() {
            let values = self
                .engine
                .batch_open_shares(ty, &share_bytes)
                .map_mpc_backend_err("batch_open_shares")?;
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

    pub(crate) fn random_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        self.ensure_ready()?;
        self.engine
            .randomness_ops()
            .map_mpc_backend_err("randomness_ops")?
            .random_share(ty)
            .map_mpc_backend_err("random_share")
    }

    pub(crate) fn random_integer_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        self.ensure_ready()?;
        self.engine
            .randomness_ops()
            .map_mpc_backend_err("randomness_ops")?
            .random_integer_share(ty)
            .map_mpc_backend_err("random_integer_share")
    }

    pub(crate) fn open_share_as_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<Vec<u8>> {
        self.ensure_ready()?;
        let share_data = self.materialize_public_share(share_data)?;
        self.engine
            .field_open_ops()
            .map_mpc_backend_err("field_open_ops")?
            .open_share_as_field(ty, share_data.as_bytes())
            .map_mpc_backend_err("open_share_as_field")
    }

    pub(crate) fn open_share_in_exp_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.ensure_ready()?;
        let share_data = self.materialize_public_share(share_data)?;
        self.engine
            .open_in_exp_ops()
            .map_mpc_backend_err("open_in_exp_ops")?
            .open_share_in_exp(ty, share_data.as_bytes(), generator_bytes)
            .map_mpc_backend_err("open_share_in_exp")
    }

    pub(crate) fn open_share_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.ensure_ready()?;
        let share_data = self.materialize_public_share(share_data)?;
        self.engine
            .open_in_exp_ops()
            .map_mpc_backend_err("open_in_exp_ops")?
            .open_share_in_exp_group(group, ty, share_data.as_bytes(), generator_bytes)
            .map_mpc_backend_err("open_share_in_exp_group")
    }
}
