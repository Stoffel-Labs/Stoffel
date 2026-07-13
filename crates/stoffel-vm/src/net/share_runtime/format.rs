use crate::error::{VmError, VmResult};
use stoffel_vm_types::core_types::ShareData;

pub(crate) fn ensure_matching_share_data_format(
    operation: &'static str,
    left: &ShareData,
    right: &ShareData,
) -> VmResult<()> {
    // Public-domain shares have no backend representation until an operation
    // actually needs bytes. They are compatible with either representation;
    // the materializer will produce the configured engine's native format.
    if left.public_input().is_some() || right.public_input().is_some() {
        return Ok(());
    }
    let left = left.format();
    let right = right.format();
    if left == right {
        Ok(())
    } else {
        Err(VmError::ShareDataFormatMismatch {
            operation,
            left: left.as_str(),
            right: right.as_str(),
        })
    }
}

pub(super) fn ensure_homogeneous_share_data_format(
    operation: &'static str,
    shares: &[ShareData],
) -> VmResult<()> {
    let mut represented = shares
        .iter()
        .enumerate()
        .filter(|(_, share)| share.public_input().is_none());
    let Some((_, first)) = represented.next() else {
        return Ok(());
    };
    let expected = first.format();
    for (index, share) in represented {
        let actual = share.format();
        if actual != expected {
            return Err(VmError::ShareDataBatchFormatMismatch {
                operation,
                expected: expected.as_str(),
                actual: actual.as_str(),
                index,
            });
        }
    }
    Ok(())
}
