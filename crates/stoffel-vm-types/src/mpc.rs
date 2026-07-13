//! Backend-independent MPC execution limits shared by the compiler and runtime.

/// Environment override for the number of secret-pair multiply operands in one
/// HoneyBadger multiplication session.
pub const HONEYBADGER_MUL_MAX_PAIRS_PER_SESSION_ENV: &str = "STOFFEL_HB_MUL_MAX_PAIRS_PER_SESSION";

/// Number of `(threshold + 1)` reconstruction groups accepted by the default
/// HoneyBadger multiplication session.
pub const DEFAULT_HONEYBADGER_MUL_BATCH_RECON_CHUNKS: usize = 128;

/// The default number of pairwise products HoneyBadger can execute in one
/// online round for a topology with Byzantine threshold `threshold`.
///
/// `override_pairs` is deliberately explicit: callers decide where process
/// configuration is read, keeping this shared capability calculation pure.
pub const fn honeybadger_mul_batch_capacity(
    threshold: usize,
    override_pairs: Option<usize>,
) -> usize {
    if let Some(value) = override_pairs {
        return if value == 0 { 1 } else { value };
    }
    DEFAULT_HONEYBADGER_MUL_BATCH_RECON_CHUNKS.saturating_mul(threshold.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honeybadger_capacity_tracks_threshold_and_override() {
        assert_eq!(honeybadger_mul_batch_capacity(0, None), 128);
        assert_eq!(honeybadger_mul_batch_capacity(1, None), 256);
        assert_eq!(honeybadger_mul_batch_capacity(2, None), 384);
        assert_eq!(honeybadger_mul_batch_capacity(9, Some(17)), 17);
        assert_eq!(honeybadger_mul_batch_capacity(9, Some(0)), 1);
    }
}
