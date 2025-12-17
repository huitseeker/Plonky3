use alloc::vec::Vec;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field};
use p3_matrix::Matrix;

/// A set of parameters defining a specific instance of the FRI protocol.
///
/// The const generic NUM_SIBLINGS specifies the number of sibling values in query proofs:
/// - NUM_SIBLINGS = 1 (default) corresponds to arity-2 folding (log_folding_factor = 1)
/// - NUM_SIBLINGS = 3 corresponds to arity-4 folding (log_folding_factor = 2)
/// - NUM_SIBLINGS = 7 corresponds to arity-8 folding (log_folding_factor = 3)
/// - In general: NUM_SIBLINGS = 2^log_folding_factor - 1
#[derive(Debug)]
pub struct FriParameters<M, const NUM_SIBLINGS: usize = 1> {
    pub log_blowup: usize,
    // TODO: This parameter and FRI early stopping are not yet implemented in `CirclePcs`.
    /// Log of the size of the final polynomial.
    /// Since we fold `log_folding_factor` bits in each iteration, it must be that
    ///   log_final_poly_len \equiv log_original_poly_len \pmod log_folding_factor
    pub log_final_poly_len: usize,
    pub num_queries: usize,
    /// Number of bits for the PoW phase before sampling _each_ batching challenge.
    pub commit_proof_of_work_bits: usize,
    /// Number of bits for the PoW phase before sampling the queries.
    pub query_proof_of_work_bits: usize,
    pub mmcs: M,
    /// Log of the folding factor (arity). Stored as runtime value for calculations.
    /// Must satisfy: 2^log_folding_factor - 1 == NUM_SIBLINGS
    pub log_folding_factor: usize,
}

impl<M, const NUM_SIBLINGS: usize> FriParameters<M, NUM_SIBLINGS> {
    pub const fn blowup(&self) -> usize {
        1 << self.log_blowup
    }

    pub const fn final_poly_len(&self) -> usize {
        1 << self.log_final_poly_len
    }

    pub const fn folding_factor(&self) -> usize {
        1 << self.log_folding_factor
    }

    /// Returns the soundness bits of this FRI instance based on the
    /// [ethSTARK](https://eprint.iacr.org/2021/582) conjecture.
    ///
    /// Certain users may instead want to look at proven soundness, a more complex calculation which
    /// isn't currently supported by this crate.
    pub const fn conjectured_soundness_bits(&self) -> usize {
        self.log_blowup * self.num_queries + self.query_proof_of_work_bits
    }
}

/// Whereas `FriParameters` encompasses parameters the end user can set, `FriFoldingStrategy` is
/// set by the PCS calling FRI, and abstracts over implementation details of the PCS.
pub trait FriFoldingStrategy<F: Field, EF: ExtensionField<F>> {
    type InputProof;
    type InputError: Debug;

    /// We can ask FRI to sample extra query bits (LSB) for our own purposes.
    /// They will be passed to our callbacks, but ignored (shifted off) by FRI.
    fn extra_query_index_bits(&self) -> usize;

    /// Log of the folding factor (arity). Defaults to 1 (folding factor of 2).
    fn log_folding_factor(&self) -> usize {
        1
    }

    /// Fold a row, returning a single column.
    /// Supporting arbitrary folding width that is a power of 2.
    fn fold_row(
        &self,
        index: usize,
        log_height: usize,
        beta: EF,
        evals: impl Iterator<Item = EF>,
    ) -> EF;

    /// Same as applying fold_row to every row, possibly faster.
    fn fold_matrix<M: Matrix<EF>>(&self, beta: EF, m: M) -> Vec<EF>;
}

/// Creates a minimal set of `FriParameters` for testing purposes.
/// These parameters are designed to reduce computational cost during tests.
/// Uses default arity-2 folding (NUM_SIBLINGS = 1).
pub const fn create_test_fri_params<Mmcs>(
    mmcs: Mmcs,
    log_final_poly_len: usize,
) -> FriParameters<Mmcs, 1> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs,
        log_folding_factor: 1,
    }
}

/// Creates a minimal set of `FriParameters` for testing purposes, with zk enabled.
/// These parameters are designed to reduce computational cost during tests.
/// Uses default arity-2 folding (NUM_SIBLINGS = 1).
pub const fn create_test_fri_params_zk<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs, 1> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs,
        log_folding_factor: 1,
    }
}

/// Creates a set of `FriParameters` suitable for benchmarking.
/// These parameters represent typical settings used in production-like scenarios.
/// Uses default arity-2 folding (NUM_SIBLINGS = 1).
pub const fn create_benchmark_fri_params<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs, 1> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs,
        log_folding_factor: 1,
    }
}

/// Creates a set of `FriParameters` suitable for benchmarking with zk enabled.
/// These parameters represent typical settings used in production-like scenarios.
/// Uses default arity-2 folding (NUM_SIBLINGS = 1).
pub const fn create_benchmark_fri_params_zk<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs, 1> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs,
        log_folding_factor: 1,
    }
}

// ============================================================================
// Type aliases for common folding arities
// ============================================================================

/// Arity-2 FRI parameters (default, 1 sibling per fold)
pub type FriParameters2<M> = FriParameters<M, 1>;

/// Arity-4 FRI parameters (3 siblings per fold)
pub type FriParameters4<M> = FriParameters<M, 3>;

/// Arity-8 FRI parameters (7 siblings per fold)
pub type FriParameters8<M> = FriParameters<M, 7>;
