use p3_poseidon2::{matmul_internal, DiffusionPermutation};
use p3_symmetric::Permutation;

use crate::{
    DiffusionMatrixMersenne31, Mersenne31, PackedMersenne31AVX2, MATRIX_DIAG_16_MERSENNE31,
};

impl Permutation<[PackedMersenne31AVX2; 16]> for DiffusionMatrixMersenne31 {
    fn permute_mut(&self, state: &mut [PackedMersenne31AVX2; 16]) {
        matmul_internal::<Mersenne31, PackedMersenne31AVX2, 16>(state, MATRIX_DIAG_16_MERSENNE31);
    }
}

impl DiffusionPermutation<PackedMersenne31AVX2, 16> for DiffusionMatrixMersenne31 {}

#[cfg(test)]
mod tests {
    use p3_field::AbstractField;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use rand::Rng;

    use crate::{DiffusionMatrixMersenne31, Mersenne31, PackedMersenne31AVX2};

    type F = Mersenne31;
    const WIDTH: usize = 16;
    const D: u64 = 5;
    type Perm16 = Poseidon2<F, Poseidon2ExternalMatrixGeneral, DiffusionMatrixMersenne31, WIDTH, D>;

    /// Test that the output is the same as the scalar version on a random input.
    #[test]
    fn test_avx2_poseidon2_width_16() {
        let mut rng = rand::thread_rng();

        // Our Poseidon2 implementation.
        let poseidon2 = Perm16::new_from_rng_128(
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixMersenne31,
            &mut rng,
        );

        let input: [F; 16] = rng.gen();

        let mut expected = input;
        poseidon2.permute_mut(&mut expected);

        let mut avx2_input = input.map(PackedMersenne31AVX2::from_f);
        poseidon2.permute_mut(&mut avx2_input);

        let avx2_output = avx2_input.map(|x| x.0[0]);

        assert_eq!(avx2_output, expected);
    }
}
