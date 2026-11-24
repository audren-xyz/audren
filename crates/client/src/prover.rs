//! BN254 Groth16 prover wrapper (`AudrenProver`) over `audren-circuits`.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{ProvingKey, VerifyingKey};
use audren_circuits::{
    deserialize_pk_compressed,
    joinsplit::{JoinSplit4AryCircuit, JoinSplitInputWitness, JoinSplitOutputWitness},
    load_canonical_joinsplit_keys,
    note::{derive_asset_id, JoinSplitPublicInputs},
    poseidon::fr_to_be_bytes,
    serialize_pk_compressed,
    solana_export::proof_to_solana_compressed_192,
    try_prove_joinsplit, verify_joinsplit_offchain,
};
use audren_core::instruction::GROTH16_PROOF_LEN;
use rand::{CryptoRng, RngCore};
use solana_address::Address;

use crate::ClientError;

/// Canonical `asset_id` for SOL/WSOL (`None`) or any SPL / Token-2022 mint (`Some(&mint)`).
pub fn asset_id_for_mint(mint: Option<&Address>) -> Fr {
    match mint {
        None => derive_asset_id(&audren_core::WSOL_MINT),
        Some(m) => derive_asset_id(&m.to_bytes()),
    }
}

/// Canonical 32-byte BE `asset_id` for SOL/WSOL (`None`) or any SPL / Token-2022 mint (`Some(&mint)`).
pub fn asset_id_bytes_for_mint(mint: Option<&Address>) -> [u8; 32] {
    fr_to_be_bytes(&asset_id_for_mint(mint))
}

/// Proof output bundle ready for Transaction v1 (`0x81`) serialization.
#[derive(Clone, Debug)]
pub struct JoinSplitProofBundle {
    pub proof_192: [u8; GROTH16_PROOF_LEN],
    pub nf0: [u8; 32],
    pub nf1: [u8; 32],
    pub cm0: [u8; 32],
    pub cm1: [u8; 32],
    pub cm2: [u8; 32],
    pub public_input_hash: [u8; 32],
    pub public_inputs: JoinSplitPublicInputs,
}

/// Holds the BN254 Groth16 proving key for the frozen `JoinSplit4AryCircuit` (`17,861` R1CS).
#[derive(Clone)]
pub struct AudrenProver {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

impl AudrenProver {
    /// Load the canonical Groth16 ceremony proving & verifying keys (offline, ~15 ms,
    /// matches `program/src/vk_generated.rs` and `ceremony/transcript.json`).
    pub fn from_canonical_pk() -> Self {
        let (pk, vk) = load_canonical_joinsplit_keys();
        Self { pk, vk }
    }

    /// Load from a compressed `ProvingKey<Bn254>` byte buffer (`~3.75 MB`, validated on curve).
    pub fn from_compressed_pk(bytes: &[u8]) -> Result<Self, ClientError> {
        let pk = deserialize_pk_compressed(bytes)
            .map_err(|_| ClientError::InvalidEncoding("invalid compressed proving key"))?;
        let vk = pk.vk.clone();
        Ok(Self { pk, vk })
    }

    /// Export compressed proving key bytes (`~3.75 MB`).
    pub fn compressed_pk_bytes(&self) -> Vec<u8> {
        serialize_pk_compressed(&self.pk)
    }

    /// Generate a 192-byte compressed BN254 Groth16 proof with caller-supplied randomness.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        circuit: JoinSplit4AryCircuit,
        rng: &mut R,
    ) -> JoinSplitProofBundle {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        self.prove_with_seed(circuit, seed)
    }

    /// Generate a deterministic 192-byte compressed BN254 Groth16 proof from an explicit 32-byte seed,
    /// checking R1CS satisfaction BEFORE proving (zero debug-build panic) and verifying off-chain
    /// satisfaction afterwards as defense-in-depth, returning `Err(ClientError::InvalidProofInput)`
    /// if the witness does not satisfy the circuit constraints.
    pub fn try_prove_with_seed(
        &self,
        circuit: JoinSplit4AryCircuit,
        seed: [u8; 32],
    ) -> Result<JoinSplitProofBundle, ClientError> {
        let public_inputs = circuit.public_inputs();
        let pub_hash = public_inputs.compute_hash();
        let proof = try_prove_joinsplit(&self.pk, circuit, seed).map_err(|_| {
            ClientError::InvalidProofInput("unsatisfied joinsplit circuit witness")
        })?;
        if !verify_joinsplit_offchain(&self.vk, &proof, pub_hash) {
            return Err(ClientError::InvalidProofInput(
                "unsatisfied joinsplit circuit witness",
            ));
        }
        let proof_192 = proof_to_solana_compressed_192(&proof);
        Ok(JoinSplitProofBundle {
            proof_192,
            nf0: fr_to_be_bytes(&public_inputs.nullifiers[0]),
            nf1: fr_to_be_bytes(&public_inputs.nullifiers[1]),
            cm0: fr_to_be_bytes(&public_inputs.out_commitments[0]),
            cm1: fr_to_be_bytes(&public_inputs.out_commitments[1]),
            cm2: fr_to_be_bytes(&public_inputs.out_commitments[2]),
            public_input_hash: fr_to_be_bytes(&pub_hash),
            public_inputs,
        })
    }

    /// Generate a deterministic 192-byte compressed BN254 Groth16 proof from an explicit 32-byte seed.
    pub fn prove_with_seed(
        &self,
        circuit: JoinSplit4AryCircuit,
        seed: [u8; 32],
    ) -> JoinSplitProofBundle {
        self.try_prove_with_seed(circuit, seed)
            .expect("joinsplit circuit witness must be satisfied")
    }

    /// Build & prove a `JoinSplit4AryCircuit` directly from witness slices.
    #[allow(clippy::too_many_arguments)]
    pub fn build_and_prove(
        &self,
        super_root: Fr,
        tx_asset_id: Fr,
        public_asset_id: Fr,
        public_amount_out: u64,
        relayer_fee_amount: u64,
        ctx_hash: Fr,
        omit_nf1: bool,
        inputs: [JoinSplitInputWitness; 2],
        outputs: [JoinSplitOutputWitness; 3],
        seed: [u8; 32],
    ) -> JoinSplitProofBundle {
        let circuit = JoinSplit4AryCircuit::new_with_options(
            super_root,
            tx_asset_id,
            public_asset_id,
            public_amount_out,
            relayer_fee_amount,
            ctx_hash,
            omit_nf1,
            inputs,
            outputs,
        );
        self.prove_with_seed(circuit, seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use audren_circuits::merkle::MerklePath4Ary;

    #[test]
    fn r2_p2_try_prove_with_seed_rejects_unsatisfied_witness_without_debug_panic() {
        let prover = AudrenProver::from_canonical_pk();
        let asset = asset_id_for_mint(None);
        // Unbalanced witness (0 in != 999_999 out): must return Err(InvalidProofInput)
        // in BOTH debug and release builds without triggering ark-groth16's debug_assert!
        let bad_circuit = JoinSplit4AryCircuit::new_with_options(
            Fr::from(0u64),
            asset,
            asset,
            999_999,
            0,
            Fr::from(0u64),
            true,
            [
                JoinSplitInputWitness {
                    spend_sk: Fr::from(1u64),
                    tweak: Fr::from(0u64),
                    asset_id: asset,
                    amount: 0,
                    blinding: Fr::from(1u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
                JoinSplitInputWitness {
                    spend_sk: Fr::from(1u64),
                    tweak: Fr::from(0u64),
                    asset_id: asset,
                    amount: 0,
                    blinding: Fr::from(2u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
            ],
            [
                JoinSplitOutputWitness::dummy(asset, Fr::from(3u64)),
                JoinSplitOutputWitness::dummy(asset, Fr::from(4u64)),
                JoinSplitOutputWitness::dummy(asset, Fr::from(5u64)),
            ],
        );
        let err = prover
            .try_prove_with_seed(bad_circuit, [0x42u8; 32])
            .expect_err("unsatisfied witness must return Err without panicking");
        assert!(matches!(err, ClientError::InvalidProofInput(_)));
    }
}
