use crate::error::{Error, Result};
use crate::types::Value;
use stoffel_vm_types::core_types::FixedPointPrecision;

pub(crate) fn encode_fixed_point_value(
    value: &Value,
    precision: FixedPointPrecision,
) -> Result<i64> {
    let scaled = match value {
        Value::I64(value) => scale_integer(i128::from(*value), precision)?,
        Value::U64(value) => scale_integer(i128::from(*value), precision)?,
        Value::Float(value) => scale_float(*value, precision)?,
        value => {
            return Err(Error::InvalidInput(format!(
                "fixed-point client input must be an integer or float, got {}",
                value.kind()
            )))
        }
    };

    validate_precision_range(scaled, precision)?;
    i64::try_from(scaled).map_err(|_| {
        Error::InvalidInput(
            "fixed-point client input is outside the VM's signed 64-bit encoded range".to_owned(),
        )
    })
}

pub(crate) fn decode_fixed_point_value(
    encoded: i64,
    precision: FixedPointPrecision,
) -> Result<f64> {
    Ok(encoded as f64 / fixed_point_scale(precision)?)
}

fn scale_integer(value: i128, precision: FixedPointPrecision) -> Result<i128> {
    let shift = u32::try_from(precision.fractional_bits()).map_err(|_| {
        Error::InvalidInput(format!(
            "fixed-point fractional-bit count {} is too large",
            precision.fractional_bits()
        ))
    })?;
    let scale = 1_i128
        .checked_shl(shift)
        .filter(|scale| *scale > 0)
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "fixed-point fractional-bit count {} is too large",
                precision.fractional_bits()
            ))
        })?;
    value.checked_mul(scale).ok_or_else(|| {
        Error::InvalidInput("fixed-point client input overflows during scaling".to_owned())
    })
}

fn scale_float(value: f64, precision: FixedPointPrecision) -> Result<i128> {
    if !value.is_finite() {
        return Err(Error::InvalidInput(
            "fixed-point client input must be finite".to_owned(),
        ));
    }

    let scaled = value * fixed_point_scale(precision)?;
    if !scaled.is_finite() {
        return Err(Error::InvalidInput(
            "fixed-point client input overflows during scaling".to_owned(),
        ));
    }

    let rounded = scaled.round();
    const I64_MIN_AS_F64: f64 = -9_223_372_036_854_775_808.0;
    const I64_MAX_EXCLUSIVE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
    if rounded < I64_MIN_AS_F64 || rounded >= I64_MAX_EXCLUSIVE_AS_F64 {
        return Err(Error::InvalidInput(
            "fixed-point client input is outside the VM's signed 64-bit encoded range".to_owned(),
        ));
    }
    Ok(i128::from(rounded as i64))
}

fn fixed_point_scale(precision: FixedPointPrecision) -> Result<f64> {
    let exponent = i32::try_from(precision.fractional_bits()).map_err(|_| {
        Error::InvalidInput(format!(
            "fixed-point fractional-bit count {} is too large",
            precision.fractional_bits()
        ))
    })?;
    let scale = 2f64.powi(exponent);
    if !scale.is_finite() {
        return Err(Error::InvalidInput(format!(
            "fixed-point scale for {} fractional bits is not finite",
            precision.fractional_bits()
        )));
    }
    Ok(scale)
}

fn validate_precision_range(encoded: i128, precision: FixedPointPrecision) -> Result<()> {
    let total_bits = precision.total_bits();
    if total_bits >= i128::BITS as usize {
        return Ok(());
    }

    let magnitude_bits = u32::try_from(total_bits - 1).map_err(|_| {
        Error::InvalidInput(format!(
            "fixed-point total-bit count {total_bits} is too large"
        ))
    })?;
    let magnitude = 1_i128.checked_shl(magnitude_bits).ok_or_else(|| {
        Error::InvalidInput(format!(
            "fixed-point total-bit count {total_bits} is too large"
        ))
    })?;
    let min = -magnitude;
    let max = magnitude - 1;
    if encoded < min || encoded > max {
        return Err(Error::InvalidInput(format!(
            "fixed-point client input encodes to {encoded}, outside the signed {total_bits}-bit range"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_fixed_point_values_encode_with_manifest_precision() {
        let precision = FixedPointPrecision::new(64, 16);

        assert_eq!(
            encode_fixed_point_value(&Value::I64(1), precision).unwrap(),
            65_536
        );
        assert_eq!(
            encode_fixed_point_value(&Value::Float(1.5), precision).unwrap(),
            98_304
        );
        assert_eq!(
            encode_fixed_point_value(&Value::I64(-2), precision).unwrap(),
            -131_072
        );
    }

    #[test]
    fn fixed_point_codec_rejects_invalid_values_and_precision_overflow() {
        let precision = FixedPointPrecision::new(32, 16);

        assert!(encode_fixed_point_value(&Value::Float(f64::NAN), precision).is_err());
        assert!(encode_fixed_point_value(&Value::I64(32_768), precision).is_err());
        assert!(encode_fixed_point_value(&Value::Bool(true), precision).is_err());
    }

    #[test]
    fn fixed_point_values_decode_with_manifest_precision() {
        let precision = FixedPointPrecision::new(64, 16);

        assert_eq!(decode_fixed_point_value(98_304, precision).unwrap(), 1.5);
        assert_eq!(decode_fixed_point_value(-32_768, precision).unwrap(), -0.5);
    }
}
