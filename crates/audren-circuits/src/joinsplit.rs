//! Minimal Frozen 2-in -> 3-out Multi-Asset Shielded Pool (MASP) `JoinSplit4AryCircuit`.
//!
//! Single unified BN254 Groth16 circuit (`DEPTH = 20`, 4-ary Poseidon4, `17,861` R1CS constraints,
//! `2^15` FFT domain) handling private transfers, merges, splits, shielded relayer fees (`cm2`),
//! public withdrawals (incl. WSOL unwrap), and `ExecViaEscrow` DeFi execution.

use ark_bn254::Fr;
use ark_ff::Field;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::{
    merkle::{constrain_merkle_root_4ary, MerklePath4Ary, TOTAL_DEPTH_4ARY},
    note::{
        compute_dummy_nullifier, compute_note_commitment, compute_real_nullifier,
        constrain_canonical_note_output, constrain_public_input_hash, derive_nullifier_key,
        derive_spend_pk, derive_stealth_owner, enforce_u64_range, JoinSplitPublicInputs,
        DOMAIN_DUMMY_NF, DOMAIN_NK, DOMAIN_NOTE, DOMAIN_NULLIFIER, DOMAIN_PK, DOMAIN_STEALTH,
    },
    poseidon::{poseidon2, poseidon_hash_var},
};

#[derive(Clone)]
pub struct JoinSplitInputWitness {
    pub spend_sk: Fr,
    pub tweak: Fr,
    pub asset_id: Fr,
    pub amount: u64,
    pub blinding: Fr,
    pub is_dummy: bool,
    pub merkle_path: MerklePath4Ary,
}

impl core::fmt::Debug for JoinSplitInputWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinSplitInputWitness")
            .field("spend_sk", &"<redacted>")
            .field("tweak", &"<redacted>")
            .field("asset_id", &self.asset_id)
            .field("amount", &self.amount)
            .field("blinding", &"<redacted>")
            .field("is_dummy", &self.is_dummy)
            .finish_non_exhaustive()
    }
}

impl JoinSplitInputWitness {
    /// Overwrite secret witness scalars (`spend_sk`, `tweak`, `blinding`) in place using volatile
    /// writes via `zeroize` so sensitive spend keys do not linger on the stack or WASM heap.
    pub fn zeroize_secrets(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.spend_sk);
        zeroize::Zeroize::zeroize(&mut self.tweak);
        zeroize::Zeroize::zeroize(&mut self.blinding);
    }
}

#[derive(Clone)]
pub struct JoinSplitOutputWitness {
    pub stealth_owner: Fr,
    pub asset_id: Fr,
    pub amount: u64,
    pub blinding: Fr,
}

impl core::fmt::Debug for JoinSplitOutputWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinSplitOutputWitness")
            .field("stealth_owner", &self.stealth_owner)
            .field("asset_id", &self.asset_id)
            .field("amount", &self.amount)
            .field("blinding", &"<redacted>")
            .finish()
    }
}

impl JoinSplitOutputWitness {
    pub fn zeroize_secrets(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.blinding);
    }

    pub fn dummy(asset_id: Fr, blinding: Fr) -> Self {
        Self {
            stealth_owner: Fr::from(0u64),
            asset_id,
            amount: 0,
            blinding,
        }
    }

    pub fn commitment(&self) -> Fr {
        compute_note_commitment(self.stealth_owner, self.asset_id, self.amount, self.blinding)
    }
}

/// Complete witness for a 2-in -> 3-out MASP `JoinSplit` (4-ary Depth-20 = `2^40` notes).
#[derive(Clone)]
pub struct JoinSplit4AryCircuit {
    pub public_input_hash: Fr,
    pub super_root: Fr,
    pub tx_asset_id: Fr,
    pub public_asset_id: Fr,
    pub public_amount_out: u64,
    pub relayer_fee_amount: u64,
    pub ctx_hash: Fr,
    /// When `true`, input slot 1 MUST be a zero-value dummy (`is_dummy == true`) and `nf1` is
    /// constrained to `0` so the on-chain verifier omits the 2nd `NullifierPDA`.
    pub omit_nf1: bool,
    pub inputs: [JoinSplitInputWitness; 2],
    pub outputs: [JoinSplitOutputWitness; 3],
}

impl core::fmt::Debug for JoinSplit4AryCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinSplit4AryCircuit")
            .field("public_input_hash", &self.public_input_hash)
            .field("super_root", &self.super_root)
            .field("tx_asset_id", &self.tx_asset_id)
            .field("public_asset_id", &self.public_asset_id)
            .field("public_amount_out", &self.public_amount_out)
            .field("relayer_fee_amount", &self.relayer_fee_amount)
            .field("ctx_hash", &self.ctx_hash)
            .field("omit_nf1", &self.omit_nf1)
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .finish()
    }
}

impl JoinSplit4AryCircuit {
    /// Wipe all secret input/output witness scalars (`spend_sk`, `tweak`, `blinding`) in place.
    pub fn zeroize_secrets(&mut self) {
        for inp in &mut self.inputs {
            inp.zeroize_secrets();
        }
        for out in &mut self.outputs {
            out.zeroize_secrets();
        }
    }
}

impl Drop for JoinSplit4AryCircuit {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl JoinSplit4AryCircuit {
    /// Deterministic empty instance for Groth16 setup / R1CS synthesis.
    pub fn empty_for_setup() -> Self {
        let zero = Fr::from(0u64);
        let dummy_in = |blinding: Fr| JoinSplitInputWitness {
            spend_sk: Fr::from(1u64),
            tweak: zero,
            asset_id: Fr::from(1u64),
            amount: 0,
            blinding,
            is_dummy: true,
            merkle_path: MerklePath4Ary::default(),
        };
        let inputs = [dummy_in(Fr::from(11u64)), dummy_in(Fr::from(22u64))];
        let outputs = [
            JoinSplitOutputWitness::dummy(Fr::from(1u64), Fr::from(33u64)),
            JoinSplitOutputWitness::dummy(Fr::from(1u64), Fr::from(44u64)),
            JoinSplitOutputWitness::dummy(Fr::from(1u64), Fr::from(55u64)),
        ];
        Self::new_with_options(zero, Fr::from(1u64), zero, 0, 0, zero, false, inputs, outputs)
    }

    /// Realistic fully non-zero 2-in -> 3-out benchmark witness (no zero-MSM shortcuts).
    pub fn realistic_benchmark_instance() -> Self {
        let spend_sk = Fr::from(0x5544_3322_1100_9988u64);
        let spend_pk = derive_spend_pk(spend_sk);
        let asset_id = crate::note::derive_asset_id(&[0xABu8; 32]);

        let tw0 = Fr::from(0x1111_2222_3333u64);
        let bl0 = Fr::from(0x4444_5555_6666u64);
        let cm0 = compute_note_commitment(derive_stealth_owner(spend_pk, tw0), asset_id, 60_000_000, bl0);

        let tw1 = Fr::from(0x7777_8888_9999u64);
        let bl1 = Fr::from(0xAAAA_BBBB_CCCCu64);
        let cm1 = compute_note_commitment(derive_stealth_owner(spend_pk, tw1), asset_id, 40_000_000, bl1);

        let mut s_shared = [[Fr::from(0u64); 3]; TOTAL_DEPTH_4ARY];
        let mut pos_shared = [0u8; TOTAL_DEPTH_4ARY];
        for (h, (row, pos)) in s_shared.iter_mut().zip(pos_shared.iter_mut()).enumerate() {
            *pos = ((h * 3 + 1) % 4) as u8;
            for (k, slot) in row.iter_mut().enumerate() {
                *slot = poseidon2(Fr::from((h as u64 + 1) * 100 + k as u64), asset_id);
            }
        }
        let mut path0 = MerklePath4Ary {
            siblings: s_shared,
            positions: pos_shared,
        };
        let mut path1 = MerklePath4Ary {
            siblings: s_shared,
            positions: pos_shared,
        };
        path0.positions[0] = 1;
        path0.siblings[0] = [s_shared[0][0], cm1, s_shared[0][2]];
        path1.positions[0] = 2;
        path1.siblings[0] = [s_shared[0][0], cm0, s_shared[0][2]];

        let super_root = path0.compute_root(cm0);
        debug_assert_eq!(super_root, path1.compute_root(cm1));

        let bob_pk = derive_spend_pk(Fr::from(0x9876_5432_10FFu64));
        let relayer_pk = derive_spend_pk(Fr::from(0xDEAD_BEEF_CAFEu64));

        Self::new_with_options(
            super_root,
            asset_id,
            Fr::from(0u64),
            0,
            0,
            poseidon2(Fr::from(42u64), super_root),
            false,
            [
                JoinSplitInputWitness {
                    spend_sk,
                    tweak: tw0,
                    asset_id,
                    amount: 60_000_000,
                    blinding: bl0,
                    is_dummy: false,
                    merkle_path: path0,
                },
                JoinSplitInputWitness {
                    spend_sk,
                    tweak: tw1,
                    asset_id,
                    amount: 40_000_000,
                    blinding: bl1,
                    is_dummy: false,
                    merkle_path: path1,
                },
            ],
            [
                JoinSplitOutputWitness {
                    stealth_owner: derive_stealth_owner(bob_pk, Fr::from(0x1001u64)),
                    asset_id,
                    amount: 75_000_000,
                    blinding: Fr::from(0x2001u64),
                },
                JoinSplitOutputWitness {
                    stealth_owner: derive_stealth_owner(spend_pk, Fr::from(0x1002u64)),
                    asset_id,
                    amount: 24_750_000,
                    blinding: Fr::from(0x2002u64),
                },
                JoinSplitOutputWitness {
                    stealth_owner: derive_stealth_owner(relayer_pk, Fr::from(0x1003u64)),
                    asset_id,
                    amount: 250_000,
                    blinding: Fr::from(0x2003u64),
                },
            ],
        )
    }

    /// Full constructor supporting both padded (`omit_nf1 = false`) and economy (`omit_nf1 = true`) modes.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        super_root: Fr,
        tx_asset_id: Fr,
        public_asset_id: Fr,
        public_amount_out: u64,
        relayer_fee_amount: u64,
        ctx_hash: Fr,
        omit_nf1: bool,
        inputs: [JoinSplitInputWitness; 2],
        outputs: [JoinSplitOutputWitness; 3],
    ) -> Self {
        let mut nullifiers = [Fr::from(0u64); 2];
        for i in 0..2 {
            let inp = &inputs[i];
            let nk = derive_nullifier_key(inp.spend_sk);
            if i == 1 && omit_nf1 {
                nullifiers[1] = Fr::from(0u64);
            } else if inp.is_dummy {
                nullifiers[i] = compute_dummy_nullifier(nk, inp.blinding);
            } else {
                let spend_pk = derive_spend_pk(inp.spend_sk);
                let stealth = derive_stealth_owner(spend_pk, inp.tweak);
                let cm = compute_note_commitment(stealth, inp.asset_id, inp.amount, inp.blinding);
                let leaf_idx = inp.merkle_path.global_leaf_index();
                nullifiers[i] = compute_real_nullifier(nk, cm, leaf_idx);
            }
        }
        let out_commitments = [
            outputs[0].commitment(),
            outputs[1].commitment(),
            outputs[2].commitment(),
        ];
        let pub_in = JoinSplitPublicInputs {
            super_root,
            nullifiers,
            out_commitments,
            public_asset_id,
            public_amount_out,
            relayer_fee_amount,
            ctx_hash,
        };
        Self {
            public_input_hash: pub_in.compute_hash(),
            super_root,
            tx_asset_id,
            public_asset_id,
            public_amount_out,
            relayer_fee_amount,
            ctx_hash,
            omit_nf1,
            inputs,
            outputs,
        }
    }

    pub fn public_inputs(&self) -> JoinSplitPublicInputs {
        let mut nullifiers = [Fr::from(0u64); 2];
        for i in 0..2 {
            let inp = &self.inputs[i];
            let nk = derive_nullifier_key(inp.spend_sk);
            if i == 1 && self.omit_nf1 {
                nullifiers[1] = Fr::from(0u64);
            } else if inp.is_dummy {
                nullifiers[i] = compute_dummy_nullifier(nk, inp.blinding);
            } else {
                let spend_pk = derive_spend_pk(inp.spend_sk);
                let stealth = derive_stealth_owner(spend_pk, inp.tweak);
                let cm = compute_note_commitment(stealth, inp.asset_id, inp.amount, inp.blinding);
                nullifiers[i] =
                    compute_real_nullifier(nk, cm, inp.merkle_path.global_leaf_index());
            }
        }
        JoinSplitPublicInputs {
            super_root: self.super_root,
            nullifiers,
            out_commitments: [
                self.outputs[0].commitment(),
                self.outputs[1].commitment(),
                self.outputs[2].commitment(),
            ],
            public_asset_id: self.public_asset_id,
            public_amount_out: self.public_amount_out,
            relayer_fee_amount: self.relayer_fee_amount,
            ctx_hash: self.ctx_hash,
        }
    }
}

impl ConstraintSynthesizer<Fr> for JoinSplit4AryCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let zero = FpVar::Constant(Fr::from(0u64));
        let one = FpVar::Constant(Fr::from(1u64));

        // Single Groth16 public input: `public_input_hash`
        let pub_hash_var = FpVar::new_input(cs.clone(), || Ok(self.public_input_hash))?;

        let super_root = FpVar::new_witness(cs.clone(), || Ok(self.super_root))?;
        let tx_asset_id = FpVar::new_witness(cs.clone(), || Ok(self.tx_asset_id))?;
        let public_asset_id = FpVar::new_witness(cs.clone(), || Ok(self.public_asset_id))?;
        let public_amount_out =
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.public_amount_out)))?;
        let relayer_fee_amount =
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.relayer_fee_amount)))?;
        let ctx_hash = FpVar::new_witness(cs.clone(), || Ok(self.ctx_hash))?;
        let omit_nf1 = Boolean::new_witness(cs.clone(), || Ok(self.omit_nf1))?;

        // Enforce `tx_asset_id != 0` strictly in R1CS
        let tx_asset_inv = FpVar::new_witness(cs.clone(), || {
            Ok(self.tx_asset_id.inverse().unwrap_or(Fr::from(0u64)))
        })?;
        (&tx_asset_id * &tx_asset_inv).enforce_equal(&one)?;

        // Strict u64 range checks on BOTH `public_amount_out` AND `relayer_fee_amount`
        let _ = enforce_u64_range(cs.clone(), &public_amount_out)?;
        let _ = enforce_u64_range(cs.clone(), &relayer_fee_amount)?;

        // Asset binding on BOTH `public_amount_out` AND `relayer_fee_amount`
        let pub_asset_diff = &public_asset_id - &tx_asset_id;
        (&public_amount_out * &pub_asset_diff).enforce_equal(&zero)?;
        (&relayer_fee_amount * &pub_asset_diff).enforce_equal(&zero)?;

        let mut sum_in = FpVar::Constant(Fr::from(0u64));
        let mut nullifiers: Vec<FpVar<Fr>> = Vec::with_capacity(2);

        for (i, inp) in self.inputs.iter().enumerate() {
            let spend_sk = FpVar::new_witness(cs.clone(), || Ok(inp.spend_sk))?;
            let tweak = FpVar::new_witness(cs.clone(), || Ok(inp.tweak))?;
            let asset_id = FpVar::new_witness(cs.clone(), || Ok(inp.asset_id))?;
            let amount = FpVar::new_witness(cs.clone(), || Ok(Fr::from(inp.amount)))?;
            let blinding = FpVar::new_witness(cs.clone(), || Ok(inp.blinding))?;
            let is_dummy = Boolean::new_witness(cs.clone(), || Ok(inp.is_dummy))?;

            let checked_asset = FpVar::conditionally_select(&is_dummy, &tx_asset_id, &asset_id)?;
            checked_asset.enforce_equal(&tx_asset_id)?;

            let _ = enforce_u64_range(cs.clone(), &amount)?;
            let dummy_amt = FpVar::conditionally_select(&is_dummy, &amount, &zero)?;
            dummy_amt.enforce_equal(&zero)?;

            let spend_pk = poseidon_hash_var(
                cs.clone(),
                &[FpVar::Constant(Fr::from(DOMAIN_PK)), spend_sk.clone()],
            )?;
            let nk = poseidon_hash_var(
                cs.clone(),
                &[FpVar::Constant(Fr::from(DOMAIN_NK)), spend_sk],
            )?;
            let stealth_owner = poseidon_hash_var(
                cs.clone(),
                &[FpVar::Constant(Fr::from(DOMAIN_STEALTH)), spend_pk, tweak],
            )?;
            let cm = poseidon_hash_var(
                cs.clone(),
                &[
                    FpVar::Constant(Fr::from(DOMAIN_NOTE)),
                    stealth_owner,
                    asset_id,
                    amount.clone(),
                    blinding.clone(),
                ],
            )?;

            let (computed_root, leaf_index) =
                constrain_merkle_root_4ary(cs.clone(), &cm, &inp.merkle_path)?;
            let root_check = FpVar::conditionally_select(&is_dummy, &super_root, &computed_root)?;
            root_check.enforce_equal(&super_root)?;

            let real_nf = poseidon_hash_var(
                cs.clone(),
                &[
                    FpVar::Constant(Fr::from(DOMAIN_NULLIFIER)),
                    nk.clone(),
                    cm,
                    leaf_index,
                ],
            )?;
            let dummy_nf = poseidon_hash_var(
                cs.clone(),
                &[FpVar::Constant(Fr::from(DOMAIN_DUMMY_NF)), nk, blinding],
            )?;
            let raw_nf = FpVar::conditionally_select(&is_dummy, &dummy_nf, &real_nf)?;

            let nf = if i == 0 {
                let nf0_inv = FpVar::new_witness(cs.clone(), || {
                    Ok(raw_nf.value()?.inverse().unwrap_or(Fr::from(0u64)))
                })?;
                (&raw_nf * &nf0_inv).enforce_equal(&one)?;
                raw_nf
            } else {
                let not_dummy1 = &one - FpVar::from(is_dummy);
                (FpVar::from(omit_nf1.clone()) * &not_dummy1).enforce_equal(&zero)?;

                let final_nf1 = FpVar::conditionally_select(&omit_nf1, &zero, &raw_nf)?;
                let nf1_nz_check = FpVar::conditionally_select(&omit_nf1, &one, &final_nf1)?;
                let nf1_nz_inv = FpVar::new_witness(cs.clone(), || {
                    Ok(nf1_nz_check.value()?.inverse().unwrap_or(Fr::from(0u64)))
                })?;
                (&nf1_nz_check * &nf1_nz_inv).enforce_equal(&one)?;
                final_nf1
            };

            nullifiers.push(nf);
            sum_in += amount;
        }

        // Distinct nullifiers `(nf_0 - nf_1) * inv == 1`
        let nf_diff = &nullifiers[0] - &nullifiers[1];
        let nf_diff_inv = FpVar::new_witness(cs.clone(), || {
            let d = nf_diff.value()?;
            Ok(d.inverse().unwrap_or(Fr::from(0u64)))
        })?;
        (&nf_diff * &nf_diff_inv).enforce_equal(&one)?;

        // 3 outputs
        let mut sum_out = FpVar::Constant(Fr::from(0u64));
        let mut out_cms: Vec<FpVar<Fr>> = Vec::with_capacity(3);
        for out in &self.outputs {
            let out_owner = FpVar::new_witness(cs.clone(), || Ok(out.stealth_owner))?;
            let out_asset = FpVar::new_witness(cs.clone(), || Ok(out.asset_id))?;
            let out_amount = FpVar::new_witness(cs.clone(), || Ok(Fr::from(out.amount)))?;
            let out_blinding = FpVar::new_witness(cs.clone(), || Ok(out.blinding))?;

            out_asset.enforce_equal(&tx_asset_id)?;

            let cm = constrain_canonical_note_output(
                cs.clone(),
                &out_owner,
                &out_asset,
                &out_amount,
                &out_blinding,
            )?;
            out_cms.push(cm);
            sum_out += out_amount;
        }

        // Strict value conservation
        sum_in.enforce_equal(&(&sum_out + &public_amount_out + &relayer_fee_amount))?;

        let shift64 = FpVar::Constant(Fr::from(1u128 << 64));
        let packed_amounts = &public_amount_out + (&relayer_fee_amount * &shift64);

        let nf_arr: [FpVar<Fr>; 2] = nullifiers.try_into().unwrap();
        let cm_arr: [FpVar<Fr>; 3] = out_cms.try_into().unwrap();
        let computed_pub_hash = constrain_public_input_hash(
            cs,
            &super_root,
            &nf_arr,
            &cm_arr,
            &public_asset_id,
            &packed_amounts,
            &ctx_hash,
        )?;
        computed_pub_hash.enforce_equal(&pub_hash_var)?;
        Ok(())
    }
}
