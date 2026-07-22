use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{
    self, apply_standing_preproc_plan, standing_preproc_snapshot, OwnedPreprocBundle,
    PoolAvailability, PreprocBlob, PreprocKeyScope, PreprocTargets, TakenPreproc,
};
pub use crate::storage::preproc::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::rand::SeedableRng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
use stoffelmpc_mpc::honeybadger::fpmul::f256::Gf256;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::HoneyBadgerError;

fn ensure_decoded_count(label: &str, actual: usize, expected: u32) -> Result<(), String> {
    let expected = usize::try_from(expected)
        .map_err(|_| format!("{label} expected count exceeds usize::MAX"))?;
    if actual != expected {
        return Err(format!(
            "{label} decoded {actual} items, expected {expected}"
        ));
    }
    Ok(())
}

fn preprocessing_progress_interval() -> Option<Duration> {
    std::env::var("STOFFEL_HB_PREPROCESSING_PROGRESS_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    /// Fully async startup + preprocessing.
    pub async fn start_async(&self) -> Result<(), String> {
        self.preprocess().await
    }

    pub async fn preprocess(&self) -> Result<(), String> {
        if self.is_standing() {
            return self.preprocess_standing().await;
        }

        if self.try_load_preproc().await? {
            self.ready.store(true, Ordering::SeqCst);
            return Ok(());
        }

        {
            let mut node = self.clone_node().await;
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            let party_id = self.topology.party_id();
            let started = Instant::now();
            let progress_done = Arc::new(AtomicBool::new(false));
            let progress_handle = preprocessing_progress_interval().map(|interval| {
                let progress_done = Arc::clone(&progress_done);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(interval).await;
                        if progress_done.load(Ordering::SeqCst) {
                            break;
                        }
                        eprintln!(
                            "[hb preprocessing progress] party={} elapsed_ms={}",
                            party_id,
                            started.elapsed().as_millis()
                        );
                    }
                })
            });

            let result = node
                .run_preprocessing(self.protocol_net.clone(), &mut rng)
                .await;
            progress_done.store(true, Ordering::SeqCst);
            if let Some(handle) = progress_handle {
                handle.abort();
            }
            result.map_err(|e| format!("Preprocessing failed: {:?}", e))?;
        }

        self.persist_preproc().await?;

        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub(super) async fn preproc_scope(
        &self,
    ) -> Result<
        (
            Arc<dyn crate::storage::preproc::PreprocStore>,
            [u8; 32],
            PreprocKeyScope,
        ),
        String,
    > {
        let store = self.preproc_store.read().await.clone();
        let hash = *self.program_hash.read().await;
        let (store, hash) = match (store, hash) {
            (Some(s), Some(h)) => (s, h),
            _ => {
                return Err(
                    "standing preprocessing requires configured preproc store and program hash"
                        .to_owned(),
                );
            }
        };
        if self.is_standing()
            && !self
                .use_program_preproc_reservoir
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                "standing execution preprocessing is owned in memory, not persisted".to_owned(),
            );
        }
        let scope = PreprocKeyScope::new(
            hash,
            F::field_kind(),
            self.topology.n_parties(),
            self.topology.threshold(),
            self.persistent_identity(),
        );
        Ok((store, hash, scope))
    }

    /// Exact preprocessing counts configured for this standing engine.
    ///
    /// Callers include these targets in the authenticated party proposal so
    /// mismatched configurations are rejected before an interactive
    /// preprocessing protocol starts.
    pub async fn standing_preproc_targets(&self) -> Result<PreprocTargets, String> {
        let node = self.clone_node().await;
        Ok(PreprocTargets {
            beaver: preproc::u32_index(node.params.n_triples as u64, "HB beaver target")?,
            random: preproc::u32_index(node.params.n_random_shares as u64, "HB random target")?,
            prand_bit: preproc::u32_index(node.params.n_prandbit as u64, "HB prandbit target")?,
            prand_int: preproc::u32_index(node.params.n_prandint as u64, "HB prandint target")?,
        })
    }

    /// Install a destructively allocated reservoir bundle into this execution's
    /// private in-memory preprocessing pool. The bundle has no persistent
    /// execution lane: dropping it before this call securely burns it.
    pub async fn activate_preallocated_standing(
        &self,
        bundle: OwnedPreprocBundle,
    ) -> Result<(), String> {
        if !self.is_standing() {
            return Err("preallocated activation requires standing deployment mode".to_owned());
        }
        if self
            .use_program_preproc_reservoir
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                "a program reservoir engine cannot be activated as an execution".to_owned(),
            );
        }
        let targets = self.standing_preproc_targets().await?;
        let availability = bundle.availability();
        if availability != targets {
            return Err(format!(
                "preallocated HB bundle does not match target: available={availability:?}, target={targets:?}"
            ));
        }
        self.activate_preproc_bundle(bundle).await
    }

    async fn activate_preproc_bundle(&self, bundle: OwnedPreprocBundle) -> Result<(), String> {
        fn decode<T>(
            item: Option<TakenPreproc>,
            label: &str,
            decode: impl FnOnce(&[u8], u32) -> Result<Vec<T>, String>,
        ) -> Result<Option<Vec<T>>, String> {
            item.map(|item| {
                let expected = item.count;
                let decoded = decode(&item.data, item.item_size)?;
                ensure_decoded_count(label, decoded.len(), expected)?;
                Ok(decoded)
            })
            .transpose()
        }

        let beaver = decode(
            bundle.beaver,
            "preallocated Beaver triples",
            |data, item_size| {
                preproc::deserialize_beaver_triples::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        let random = decode(
            bundle.random,
            "preallocated random shares",
            |data, item_size| {
                preproc::deserialize_robust_shares::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        let prand_bit = decode(
            bundle.prand_bit,
            "preallocated PRandBit shares",
            |data, item_size| {
                preproc::deserialize_prandbit_shares::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        let prand_int = decode(
            bundle.prand_int,
            "preallocated PRandInt shares",
            |data, item_size| {
                preproc::deserialize_robust_shares::<F>(data, item_size, 0)
                    .map_err(|error| error.to_string())
            },
        )?;
        self.clone_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(beaver, None, random, None, prand_bit, prand_int);
        self.ready.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub async fn standing_preproc_snapshot(&self) -> Result<StandingPreprocSnapshot, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        standing_preproc_snapshot(store.as_ref(), scope)
            .await
            .map_err(String::from)
    }

    /// Validate party-indexed snapshots and install the only plan that a
    /// multi-party standing execution may use. Callers exchange snapshots over
    /// the execution-scoped control route before calling [`Self::preprocess`].
    pub async fn install_standing_preproc_plan(
        &self,
        snapshots: Vec<StandingPreprocSnapshot>,
        fresh_generation_id: [u8; 32],
    ) -> Result<StandingPreprocPlan, String> {
        if snapshots.len() != self.topology.n_parties() {
            return Err(format!(
                "standing preprocessing agreement received {} inventories, expected {}",
                snapshots.len(),
                self.topology.n_parties()
            ));
        }
        let local = self.standing_preproc_snapshot().await?;
        let local_index = self.topology.party_id();
        if snapshots.get(local_index) != Some(&local) {
            return Err(format!(
                "standing preprocessing local inventory changed during agreement: local={local:?}, exchanged={:?}",
                snapshots.get(local_index)
            ));
        }
        let plan = agree_standing_preproc_plan(
            self.standing_preproc_targets().await?,
            &snapshots,
            fresh_generation_id,
        )?;
        *self.standing_preproc_plan.lock().await = Some(plan);
        Ok(plan)
    }

    async fn preprocess_standing(&self) -> Result<(), String> {
        let targets = self.standing_preproc_targets().await?;
        let plan = if self.topology.n_parties() == 1 {
            agree_standing_preproc_plan(
                targets,
                &[self.standing_preproc_snapshot().await?],
                crate::net::session::ExecutionId::new().into_bytes(),
            )?
        } else {
            self.standing_preproc_plan.lock().await.take().ok_or_else(|| {
                "multi-party standing preprocessing requires a party-agreed inventory plan before protocol startup"
                    .to_owned()
            })?
        };
        let (store, _hash, scope) = self.preproc_scope().await?;
        let final_snapshot = apply_standing_preproc_plan(store.as_ref(), scope, plan, |needed| {
            self.top_up_exact(needed)
        })
        .await?;
        let final_available = final_snapshot.availability();
        if final_snapshot.generation_id != Some(plan.generation_id)
            || !final_available.covers(targets)
        {
            return Err(format!(
                "standing preprocessing top-up did not reach agreed plan: plan={plan:?}, final={final_snapshot:?}"
            ));
        }

        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn top_up_exact(&self, needed: PoolAvailability) -> Result<(), String> {
        if needed == PoolAvailability::default() {
            return Ok(());
        }
        let (store, _hash, scope) = self.preproc_scope().await?;
        let mut node = self.clone_node().await;
        node.params.n_triples = needed.beaver as usize;
        node.params.n_random_shares = needed.random as usize;
        node.params.n_prandbit = needed.prand_bit as usize;
        node.params.n_prandint = needed.prand_int as usize;

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.protocol_net.clone(), &mut rng)
            .await
            .map_err(|e| format!("Failed to top up preprocessing material: {:?}", e))?;

        let mut to_append = Vec::new();
        {
            let mut prep = node.preprocessing_material.lock().await;
            let lengths = prep.length();
            if lengths.beaver_triples > 0 {
                let items = prep
                    .take_beaver_triples(lengths.beaver_triples)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_beaver_triples::<F>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated beaver")?;
                to_append.push((scope.beaver_triple(), item_size, added, data));
            }
            if lengths.random_shr > 0 {
                let items = prep
                    .take_random_shares(lengths.random_shr)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_robust_shares::<F>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated random")?;
                to_append.push((scope.random_share(), item_size, added, data));
            }
            if lengths.prandbit > 0 {
                let items = prep
                    .take_prandbit_shares(lengths.prandbit)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_prandbit_shares::<F>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated prandbit")?;
                to_append.push((scope.prand_bit(), item_size, added, data));
            }
            if lengths.prandint > 0 {
                let items = prep
                    .take_prandint_shares(lengths.prandint)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_robust_shares::<F>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated prandint")?;
                to_append.push((scope.prand_int(), item_size, added, data));
            }
        }

        for (key, item_size, added, data) in to_append {
            store.append_items(&key, item_size, added, &data).await?;
        }

        Ok(())
    }

    /// Try to load preprocessing material from the persistent store.
    /// Returns `true` if material was loaded, `false` if nothing available.
    async fn try_load_preproc(&self) -> Result<bool, String> {
        let store = self.preproc_store.read().await.clone();
        let hash = *self.program_hash.read().await;
        let (store, hash) = match (store, hash) {
            (Some(store), Some(hash)) => (store, hash),
            _ => return Ok(false),
        };
        let identity = self.persistent_identity();
        let scope = PreprocKeyScope::new(
            hash,
            F::field_kind(),
            self.topology.n_parties(),
            self.topology.threshold(),
            identity,
        );
        let requested = store.scope_availability(&scope).await?;
        if requested == PoolAvailability::default() {
            return Ok(false);
        }

        // One transaction removes the complete bundle before it reaches RAM.
        // Concurrent engines therefore cannot observe or consume the same
        // correlated material.
        let bundle = store.take_bundle_from_reservoir(&scope, requested).await?;
        let loaded = bundle.availability();
        self.activate_preproc_bundle(bundle).await?;
        let msg = format!(
            "Loaded preprocessing material from store for program {} (identity={}, n={}, t={}, triples={}, randoms={}, prandbits={}, prandints={})",
            hex::encode(hash),
            identity,
            self.topology.n_parties(),
            self.topology.threshold(),
            loaded.beaver,
            loaded.random,
            loaded.prand_bit,
            loaded.prand_int,
        );
        eprintln!("{msg}");
        tracing::info!("{msg}");
        Ok(true)
    }

    /// Persist current preprocessing material to the store.
    ///
    /// Drains and serializes material inside the lock, then releases the lock
    /// before the async store writes to minimise lock hold time.
    async fn persist_preproc(&self) -> Result<(), String> {
        let store = self.preproc_store.read().await.clone();
        let hash = *self.program_hash.read().await;
        let (store, hash) = match (store, hash) {
            (Some(s), Some(h)) => (s, h),
            _ => return Ok(()),
        };
        let persistent_identity = self.persistent_identity();

        let scope = PreprocKeyScope::new(
            hash,
            F::field_kind(),
            self.topology.n_parties(),
            self.topology.threshold(),
            persistent_identity,
        );
        let base = scope.beaver_triple();

        let mut to_store = Vec::new();
        let mut restore_bt = None;
        let mut restore_rs = None;
        let mut restore_pb = None;
        let mut restore_pi = None;

        {
            let node = self.clone_node().await;
            let mut prep = node.preprocessing_material.lock().await;
            let _m = prep.length();
            let (n_bt, n_rs, n_pb, n_pi) =
                (_m.beaver_triples, _m.random_shr, _m.prandbit, _m.prandint);

            if n_bt > 0 {
                let items = prep
                    .take_beaver_triples(n_bt)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_beaver_triples::<F>(&items)?;
                to_store.push((
                    base.clone(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_bt = Some(items);
            }
            if n_rs > 0 {
                let items = prep
                    .take_random_shares(n_rs)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_robust_shares::<F>(&items)?;
                to_store.push((
                    scope.random_share(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_rs = Some(items);
            }
            if n_pb > 0 {
                let items = prep
                    .take_prandbit_shares(n_pb)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_prandbit_shares::<F>(&items)?;
                to_store.push((
                    scope.prand_bit(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_pb = Some(items);
            }
            if n_pi > 0 {
                let items = prep
                    .take_prandint_shares(n_pi)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_robust_shares::<F>(&items)?;
                to_store.push((
                    scope.prand_int(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                restore_pi = Some(items);
            }

            prep.add(restore_bt, None, restore_rs, None, restore_pb, restore_pi);
        }

        for (key, blob) in &to_store {
            store.store(key, blob).await?;
        }

        let msg = format!(
            "Persisted preprocessing material to store for program {} (identity={}, n={}, t={}, blobs={})",
            hex::encode(hash),
            persistent_identity,
            self.topology.n_parties(),
            self.topology.threshold(),
            to_store.len()
        );
        eprintln!("{msg}");
        tracing::info!("{msg}");
        Ok(())
    }

    pub(super) async fn reserve_random_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, String> {
        loop {
            let attempt = {
                let node = self.clone_node().await;
                let mut prep_material = node.preprocessing_material.lock().await;
                prep_material.take_random_shares(num_shares)
            };

            match attempt {
                Ok(shares) => return Ok(shares),
                Err(HoneyBadgerError::NotEnoughPreprocessing) if self.is_standing() => {
                    return Err(format!(
                        "standing execution exhausted its owned random-share bundle (need {num_shares})"
                    ));
                }
                Err(HoneyBadgerError::NotEnoughPreprocessing) => {
                    self.regenerate_random_shares(num_shares).await?;
                    continue;
                }
                Err(other) => {
                    return Err(format!("Failed to take random shares: {:?}", other));
                }
            }
        }
    }

    pub(super) async fn reserve_prandint_shares(
        &self,
        num_shares: usize,
        ty: ShareType,
    ) -> Result<Vec<RobustShare<F>>, String> {
        loop {
            let attempt = {
                let node = self.clone_node().await;
                let mut prep_material = node.preprocessing_material.lock().await;
                prep_material.take_prandint_shares(num_shares)
            };

            match attempt {
                Ok(shares) => return Ok(shares),
                Err(HoneyBadgerError::NotEnoughPreprocessing) if self.is_standing() => {
                    return Err(format!(
                        "standing execution exhausted its owned PRandInt bundle (need {num_shares})"
                    ));
                }
                Err(HoneyBadgerError::NotEnoughPreprocessing) => {
                    self.regenerate_prandint_shares(num_shares, ty).await?;
                    continue;
                }
                Err(other) => {
                    return Err(format!("Failed to take PRandInt shares: {:?}", other));
                }
            }
        }
    }

    pub(super) async fn reserve_beaver_triples(
        &self,
        num_triples: usize,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, String> {
        let node = self.clone_node().await;
        let result = node
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(num_triples)
            .map_err(|e| format!("Failed to take Beaver triples: {:?}", e));
        result
    }

    pub(super) async fn reserve_prandbit_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<(RobustShare<F>, Gf256)>, String> {
        let node = self.clone_node().await;
        let result = node
            .preprocessing_material
            .lock()
            .await
            .take_prandbit_shares(num_shares)
            .map_err(|e| format!("Failed to take PRandBit shares: {:?}", e));
        result
    }

    async fn regenerate_random_shares(&self, needed: usize) -> Result<(), String> {
        let mut node = self.clone_node().await;
        {
            let current = node.preprocessing_material.lock().await.length().random_shr;
            let target = current + needed;
            if node.params.n_random_shares < target {
                node.params.n_random_shares = target;
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.protocol_net.clone(), &mut rng)
            .await
            .map_err(|e| format!("Failed to regenerate preprocessing material: {:?}", e))
    }

    async fn regenerate_prandint_shares(&self, needed: usize, ty: ShareType) -> Result<(), String> {
        let mut node = self.clone_node().await;
        {
            let current = node.preprocessing_material.lock().await.length().prandint;
            let target = current + needed;
            if node.params.n_prandint < target {
                node.params.n_prandint = target;
            }
            if let ShareType::SecretInt { bit_length } | ShareType::SecretUInt { bit_length } = ty {
                let target_random_bits = bit_length.min(56);
                node.params.l = target_random_bits.saturating_sub(node.params.k);
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        node.run_preprocessing(self.protocol_net.clone(), &mut rng)
            .await
            .map_err(|e| {
                format!(
                    "Failed to regenerate PRandInt preprocessing material: {:?}",
                    e
                )
            })
    }

    /// Pull one pre-generated random share from the preprocessing pool.
    /// If the pool is empty, `reserve_random_shares` auto-regenerates via
    /// the RanSha protocol over the network.
    pub(super) async fn random_share_async_impl(
        &self,
        _ty: ShareType,
    ) -> Result<ShareData, String> {
        let shares = self.reserve_random_shares(1).await?;
        Self::encode_share(&shares[0]).map(|v| ShareData::Opaque(v.into()))
    }

    /// Pull one pre-generated PRandInt share from the preprocessing pool.
    pub(super) async fn random_integer_share_async_impl(
        &self,
        ty: ShareType,
    ) -> Result<ShareData, String> {
        let shares = self.reserve_prandint_shares(1, ty).await?;
        Self::encode_share(&shares[0]).map(|v| ShareData::Opaque(v.into()))
    }
}

#[cfg(test)]
mod standing_agreement_tests {
    use super::*;

    fn retained_snapshot() -> StandingPreprocSnapshot {
        StandingPreprocSnapshot {
            generation_id: Some([4; 32]),
            beaver: preproc::PreprocMeta {
                count: 16,
                consumed: 3,
                item_size: 96,
            },
            random: preproc::PreprocMeta {
                count: 20,
                consumed: 4,
                item_size: 48,
            },
            prand_bit: preproc::PreprocMeta {
                count: 8,
                consumed: 1,
                item_size: 49,
            },
            prand_int: preproc::PreprocMeta {
                count: 6,
                consumed: 2,
                item_size: 48,
            },
        }
    }

    #[test]
    fn party_agreement_rebuilds_empty_store_against_retained_peers() {
        let retained = retained_snapshot();
        let empty = StandingPreprocSnapshot::default();
        let plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 16,
                random: 16,
                prand_bit: 8,
                prand_int: 4,
            },
            &[retained, retained, empty, retained],
            [9; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Rebuild);
        assert_eq!(
            plan.needed,
            PoolAvailability {
                beaver: 16,
                random: 16,
                prand_bit: 8,
                prand_int: 4,
            }
        );
        assert_eq!(plan.generation_id, [9; 32]);
    }

    #[test]
    fn party_agreement_rebuilds_stale_cursor_before_top_up() {
        let retained = retained_snapshot();
        let mut stale = retained;
        stale.random.consumed += 1;
        let plan = agree_standing_preproc_plan(
            PoolAvailability::default(),
            &[retained, stale, retained],
            [7; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Rebuild);
        assert_eq!(plan.generation_id, [7; 32]);
    }

    #[test]
    fn same_shape_from_different_generations_rebuilds() {
        let first = retained_snapshot();
        let mut second = first;
        second.generation_id = Some([99; 32]);
        let plan =
            agree_standing_preproc_plan(first.availability(), &[first, second], [8; 32]).unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Rebuild);
        assert_eq!(plan.generation_id, [8; 32]);
    }

    #[test]
    fn retained_matching_generation_is_reused_without_changing_nonce() {
        let retained = retained_snapshot();
        let plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 13,
                random: 16,
                prand_bit: 7,
                prand_int: 4,
            },
            &[retained, retained],
            [88; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::Reuse);
        assert_eq!(plan.needed, PoolAvailability::default());
        assert_eq!(plan.generation_id, [4; 32]);
    }

    #[test]
    fn matching_inventories_choose_one_identical_deficit_and_generation() {
        let retained = retained_snapshot();
        let plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 20,
                random: 20,
                prand_bit: 10,
                prand_int: 8,
            },
            &[retained, retained, retained],
            [5; 32],
        )
        .unwrap();
        assert_eq!(plan.action, StandingPreprocAction::TopUp);
        assert_eq!(
            plan.needed,
            PoolAvailability {
                beaver: 7,
                random: 4,
                prand_bit: 3,
                prand_int: 4,
            }
        );
        assert_eq!(plan.generation_id, [5; 32]);
        let peer_plan = agree_standing_preproc_plan(
            PoolAvailability {
                beaver: 20,
                random: 20,
                prand_bit: 10,
                prand_int: 8,
            },
            &[retained, retained, retained],
            [5; 32],
        )
        .unwrap();
        assert_eq!(peer_plan, plan, "all parties must install the same plan");
    }
}
