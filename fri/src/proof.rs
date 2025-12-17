use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::Field;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use core::fmt;
use core::marker::PhantomData;

// Type aliases for common folding arities

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "Witness: Serialize, InputProof: Serialize",
    deserialize = "Witness: Deserialize<'de>, InputProof: Deserialize<'de>"
))]
pub struct FriProof<F: Field, M: Mmcs<F>, Witness, InputProof, const NUM_SIBLINGS: usize = 1> {
    pub commit_phase_commits: Vec<M::Commitment>,
    pub commit_pow_witnesses: Vec<Witness>,
    pub query_proofs: Vec<QueryProof<F, M, InputProof, NUM_SIBLINGS>>,
    pub final_poly: Vec<F>,
    pub query_pow_witness: Witness,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(
    serialize = "InputProof: Serialize",
    deserialize = "InputProof: Deserialize<'de>",
))]
pub struct QueryProof<F: Field, M: Mmcs<F>, InputProof, const NUM_SIBLINGS: usize = 1> {
    pub input_proof: InputProof,
    /// For each commit phase commitment, this contains openings of a commit phase codeword at the
    /// queried location, along with an opening proof.
    pub commit_phase_openings: Vec<CommitPhaseProofStep<F, M, NUM_SIBLINGS>>,
}

#[derive(Debug, Clone)]
pub struct CommitPhaseProofStep<F: Field, M: Mmcs<F>, const NUM_SIBLINGS: usize = 1> {
    /// The openings of the commit phase codeword at all sibling locations.
    /// For folding factor 2 (default), NUM_SIBLINGS = 1 (single sibling).
    /// For folding factor k, NUM_SIBLINGS = k-1 (all siblings except the queried index).
    pub sibling_values: [F; NUM_SIBLINGS],

    pub opening_proof: M::Proof,
}

// Custom Serialize implementation for generic array
impl<F, M, const NUM_SIBLINGS: usize> Serialize
    for CommitPhaseProofStep<F, M, NUM_SIBLINGS>
where
    F: Field + Serialize,
    M: Mmcs<F>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CommitPhaseProofStep", 2)?;

        // Serialize the array as a sequence
        state.serialize_field("sibling_values", &SerializableArray(&self.sibling_values))?;
        state.serialize_field("opening_proof", &self.opening_proof)?;
        state.end()
    }
}

// Helper struct to serialize arrays
struct SerializableArray<'a, T, const N: usize>(&'a [T; N]);

impl<'a, T: Serialize, const N: usize> Serialize for SerializableArray<'a, T, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(N))?;
        for element in self.0.iter() {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

// Custom Deserialize implementation for generic array
impl<'de, F, M, const NUM_SIBLINGS: usize> Deserialize<'de>
    for CommitPhaseProofStep<F, M, NUM_SIBLINGS>
where
    F: Field,
    M: Mmcs<F>,
    for<'a> F: Deserialize<'a>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum FieldName {
            SiblingValues,
            OpeningProof,
        }

        struct CommitPhaseProofStepVisitor<F, M, const N: usize>
        where
            F: Field,
            M: Mmcs<F>,
        {
            _phantom: PhantomData<(F, M)>,
        }

        impl<'de, F, M, const N: usize> Visitor<'de>
            for CommitPhaseProofStepVisitor<F, M, N>
        where
            F: Field,
            M: Mmcs<F>,
            for<'a> F: Deserialize<'a>,
        {
            type Value = CommitPhaseProofStep<F, M, N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct CommitPhaseProofStep")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let sibling_values = seq
                    .next_element::<Vec<F>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                let opening_proof = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                if sibling_values.len() != N {
                    return Err(serde::de::Error::invalid_length(sibling_values.len(), &self));
                }

                let sibling_array: [F; N] = sibling_values.try_into()
                    .map_err(|_| serde::de::Error::custom("failed to convert vec to array"))?;

                Ok(CommitPhaseProofStep {
                    sibling_values: sibling_array,
                    opening_proof,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut sibling_values = None;
                let mut opening_proof = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        FieldName::SiblingValues => {
                            if sibling_values.is_some() {
                                return Err(serde::de::Error::duplicate_field("sibling_values"));
                            }
                            let vec: Vec<F> = map.next_value()?;
                            if vec.len() != N {
                                return Err(serde::de::Error::invalid_length(vec.len(), &self));
                            }
                            let array: [F; N] = vec.try_into()
                                .map_err(|_| serde::de::Error::custom("failed to convert vec to array"))?;
                            sibling_values = Some(array);
                        }
                        FieldName::OpeningProof => {
                            if opening_proof.is_some() {
                                return Err(serde::de::Error::duplicate_field("opening_proof"));
                            }
                            opening_proof = Some(map.next_value()?);
                        }
                    }
                }

                let sibling_values = sibling_values
                    .ok_or_else(|| serde::de::Error::missing_field("sibling_values"))?;
                let opening_proof = opening_proof
                    .ok_or_else(|| serde::de::Error::missing_field("opening_proof"))?;

                Ok(CommitPhaseProofStep {
                    sibling_values,
                    opening_proof,
                })
            }
        }

        const FIELDS: &[&str] = &["sibling_values", "opening_proof"];
        deserializer.deserialize_struct(
            "CommitPhaseProofStep",
            FIELDS,
            CommitPhaseProofStepVisitor {
                _phantom: PhantomData,
            },
        )
    }
}

// ============================================================================
// Type aliases for common folding arities
// ============================================================================

/// Arity-2 FRI proof structures (default, 1 sibling per fold)
pub type CommitPhaseProofStep2<F, M> = CommitPhaseProofStep<F, M, 1>;
pub type QueryProof2<F, M, InputProof> = QueryProof<F, M, InputProof, 1>;
pub type FriProof2<F, M, Witness, InputProof> = FriProof<F, M, Witness, InputProof, 1>;

/// Arity-4 FRI proof structures (3 siblings per fold)
pub type CommitPhaseProofStep4<F, M> = CommitPhaseProofStep<F, M, 3>;
pub type QueryProof4<F, M, InputProof> = QueryProof<F, M, InputProof, 3>;
pub type FriProof4<F, M, Witness, InputProof> = FriProof<F, M, Witness, InputProof, 3>;

/// Arity-8 FRI proof structures (7 siblings per fold)
pub type CommitPhaseProofStep8<F, M> = CommitPhaseProofStep<F, M, 7>;
pub type QueryProof8<F, M, InputProof> = QueryProof<F, M, InputProof, 7>;
pub type FriProof8<F, M, Witness, InputProof> = FriProof<F, M, Witness, InputProof, 7>;
