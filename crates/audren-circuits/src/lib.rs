//! Audren Minimal Frozen Circuit & Prover Crate (`JoinSplit4AryCircuit`, `DEPTH = 20`,
//! `17,861` R1CS constraints, `2^15` BN254 FFT domain, `192 B` Groth16 proof).
//!
//! Compiles identically to native Rust (for `audren-client` & `audren-ffi` Swift/Kotlin) and
//! `wasm32-unknown-unknown` (for `@audren/sdk/prover` in Node.js and Browser Web Workers).

pub mod joinsplit;
pub mod merkle;
pub mod note;
pub mod poseidon;
pub mod solana_export;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{
    joinsplit::{JoinSplit4AryCircuit, JoinSplitInputWitness, JoinSplitOutputWitness},
    merkle::{MerklePath4Ary, TOTAL_DEPTH_4ARY},
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};

/// Deterministic development/Devnet setup seed (`DEV_DETERMINISTIC_VK` — MUST be replaced by
/// the public Phase-2 MPC ceremony artifact prior to Mainnet deployment).
pub const DEV_SETUP_SEED_V2: [u8; 32] = [0xA1; 32];

/// Exact fixed byte lengths for the WASM/FFI binary witness & proof ABI.
pub const WITNESS_INPUT_BYTES: usize = 32 + 32 + 32 + 8 + 32 + 1 + TOTAL_DEPTH_4ARY + (TOTAL_DEPTH_4ARY * 3 * 32); // 2,077 B
pub const WITNESS_OUTPUT_BYTES: usize = 32 + 32 + 8 + 32; // 104 B
pub const WITNESS_TOTAL_BYTES: usize = 32 + 32 + 32 + 8 + 8 + 32 + 1 + (2 * WITNESS_INPUT_BYTES) + (3 * WITNESS_OUTPUT_BYTES); // 4,611 B
pub const PROVE_OUTPUT_BYTES: usize = 192 + (6 * 32); // 384 B: proof_192 || nf0 || nf1 || cm0 || cm1 || cm2 || pub_hash

const _: () = assert!(WITNESS_INPUT_BYTES == 2_077);
const _: () = assert!(WITNESS_OUTPUT_BYTES == 104);
const _: () = assert!(WITNESS_TOTAL_BYTES == 4_611);
const _: () = assert!(PROVE_OUTPUT_BYTES == 384);

/// Deterministic setup for local tests, CI, and Devnet (replaced by MPC ceremony PK/VK for Mainnet).
pub fn setup_joinsplit_dev() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    let mut rng = ChaCha20Rng::from_seed(DEV_SETUP_SEED_V2);
    Groth16::<Bn254>::circuit_specific_setup(JoinSplit4AryCircuit::empty_for_setup(), &mut rng)
        .expect("joinsplit dev setup")
}

/// Serialize a `ProvingKey<Bn254>` to compact compressed bytes (`~3.75 MB`).
pub fn serialize_pk_compressed(pk: &ProvingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(pk.compressed_size());
    pk.serialize_compressed(&mut out).expect("serialize pk");
    out
}

/// Deserialize a compressed `ProvingKey<Bn254>` (validated on curve).
pub fn deserialize_pk_compressed(bytes: &[u8]) -> Result<ProvingKey<Bn254>, String> {
    ProvingKey::<Bn254>::deserialize_compressed(bytes).map_err(|e| e.to_string())
}

/// Generate a BN254 Groth16 proof for `JoinSplit4AryCircuit`.
pub fn prove_joinsplit(
    pk: &ProvingKey<Bn254>,
    circuit: JoinSplit4AryCircuit,
    seed: [u8; 32],
) -> Proof<Bn254> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    Groth16::<Bn254>::prove(pk, circuit, &mut rng).expect("prove joinsplit")
}

/// Verify a BN254 Groth16 proof off-chain against `VerifyingKey<Bn254>`.
pub fn verify_joinsplit_offchain(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_input_hash: Fr,
) -> bool {
    Groth16::<Bn254>::verify(vk, &[public_input_hash], proof).unwrap_or(false)
}

/// Count exact R1CS constraints, witness variables, and instance variables.
pub fn count_constraints<C: ConstraintSynthesizer<Fr>>(circuit: C) -> (usize, usize, usize) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("synthesize");
    assert!(cs.is_satisfied().unwrap(), "circuit must be satisfied");
    (
        cs.num_constraints(),
        cs.num_witness_variables(),
        cs.num_instance_variables(),
    )
}

pub fn compressed_pk_size(pk: &ProvingKey<Bn254>) -> usize {
    pk.compressed_size()
}

/// Encode a `JoinSplit4AryCircuit` witness into the exact `4,611 B` binary ABI consumed by WASM.
pub fn encode_joinsplit_witness_bytes(c: &JoinSplit4AryCircuit) -> [u8; WITNESS_TOTAL_BYTES] {
    let mut buf = [0u8; WITNESS_TOTAL_BYTES];
    let mut off = 0usize;
    let mut push = |slice: &[u8]| {
        buf[off..off + slice.len()].copy_from_slice(slice);
        off += slice.len();
    };
    push(&fr_to_be_bytes(&c.super_root));
    push(&fr_to_be_bytes(&c.tx_asset_id));
    push(&fr_to_be_bytes(&c.public_asset_id));
    push(&c.public_amount_out.to_le_bytes());
    push(&c.relayer_fee_amount.to_le_bytes());
    push(&fr_to_be_bytes(&c.ctx_hash));
    push(&[u8::from(c.omit_nf1)]);
    for inp in &c.inputs {
        push(&fr_to_be_bytes(&inp.spend_sk));
        push(&fr_to_be_bytes(&inp.tweak));
        push(&fr_to_be_bytes(&inp.asset_id));
        push(&inp.amount.to_le_bytes());
        push(&fr_to_be_bytes(&inp.blinding));
        push(&[u8::from(inp.is_dummy)]);
        push(&inp.merkle_path.positions);
        for h in 0..TOTAL_DEPTH_4ARY {
            for k in 0..3 {
                push(&fr_to_be_bytes(&inp.merkle_path.siblings[h][k]));
            }
        }
    }
    for out in &c.outputs {
        push(&fr_to_be_bytes(&out.stealth_owner));
        push(&fr_to_be_bytes(&out.asset_id));
        push(&out.amount.to_le_bytes());
        push(&fr_to_be_bytes(&out.blinding));
    }
    debug_assert_eq!(off, WITNESS_TOTAL_BYTES);
    buf
}

/// Decode the `4,611 B` binary witness ABI into `JoinSplit4AryCircuit` (strict canonical Fr checks).
pub fn decode_joinsplit_witness_bytes(buf: &[u8]) -> Result<JoinSplit4AryCircuit, i32> {
    if buf.len() != WITNESS_TOTAL_BYTES {
        return Err(-2);
    }
    let mut off = 0usize;
    let read_fr = |off: &mut usize| -> Result<Fr, i32> {
        let arr: [u8; 32] = buf[*off..*off + 32].try_into().map_err(|_| -2)?;
        *off += 32;
        fr_from_be_bytes_strict(&arr).ok_or(-3)
    };
    let read_u64 = |off: &mut usize| -> Result<u64, i32> {
        let arr: [u8; 8] = buf[*off..*off + 8].try_into().map_err(|_| -2)?;
        *off += 8;
        Ok(u64::from_le_bytes(arr))
    };

    let super_root = read_fr(&mut off)?;
    let tx_asset_id = read_fr(&mut off)?;
    let public_asset_id = read_fr(&mut off)?;
    let public_amount_out = read_u64(&mut off)?;
    let relayer_fee_amount = read_u64(&mut off)?;
    let ctx_hash = read_fr(&mut off)?;
    let omit_nf1 = buf[off] != 0;
    off += 1;

    let mut inputs_vec = Vec::with_capacity(2);
    for _ in 0..2 {
        let spend_sk = read_fr(&mut off)?;
        let tweak = read_fr(&mut off)?;
        let asset_id = read_fr(&mut off)?;
        let amount = read_u64(&mut off)?;
        let blinding = read_fr(&mut off)?;
        let is_dummy = buf[off] != 0;
        off += 1;
        let mut positions = [0u8; TOTAL_DEPTH_4ARY];
        positions.copy_from_slice(&buf[off..off + TOTAL_DEPTH_4ARY]);
        off += TOTAL_DEPTH_4ARY;
        if positions.iter().any(|&p| p > 3) {
            return Err(-3);
        }
        let mut siblings = [[Fr::from(0u64); 3]; TOTAL_DEPTH_4ARY];
        for sib_level in &mut siblings {
            for s in sib_level.iter_mut() {
                *s = read_fr(&mut off)?;
            }
        }
        inputs_vec.push(JoinSplitInputWitness {
            spend_sk,
            tweak,
            asset_id,
            amount,
            blinding,
            is_dummy,
            merkle_path: MerklePath4Ary {
                siblings,
                positions,
            },
        });
    }

    let mut outputs_vec = Vec::with_capacity(3);
    for _ in 0..3 {
        let stealth_owner = read_fr(&mut off)?;
        let asset_id = read_fr(&mut off)?;
        let amount = read_u64(&mut off)?;
        let blinding = read_fr(&mut off)?;
        outputs_vec.push(JoinSplitOutputWitness {
            stealth_owner,
            asset_id,
            amount,
            blinding,
        });
    }

    let inputs: [JoinSplitInputWitness; 2] = inputs_vec.try_into().map_err(|_| -2)?;
    let outputs: [JoinSplitOutputWitness; 3] = outputs_vec.try_into().map_err(|_| -2)?;
    Ok(JoinSplit4AryCircuit::new_with_options(
        super_root,
        tx_asset_id,
        public_asset_id,
        public_amount_out,
        relayer_fee_amount,
        ctx_hash,
        omit_nf1,
        inputs,
        outputs,
    ))
}

/// Real `wasm32-unknown-unknown` production prover exports for `@audren/sdk/prover`
/// (Node.js and Browser Web Worker — zero `wasm-bindgen` glue required).
#[cfg(target_arch = "wasm32")]
mod wasm_exports {
    use super::*;
    use std::cell::RefCell;

    fn custom_rng(buf: &mut [u8]) -> Result<(), getrandom::Error> {
        // Proving always accepts an explicit caller-supplied 32-byte CSPRNG seed;
        // this hook satisfies `getrandom` for deterministic dev PK initialization.
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(13);
        }
        Ok(())
    }
    getrandom::register_custom_getrandom!(custom_rng);

    thread_local! {
        static CACHED_PK: RefCell<Option<ProvingKey<Bn254>>> = const { RefCell::new(None) };
    }

    #[no_mangle]
    pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
        let mut buf = Vec::<u8>::with_capacity(len);
        let ptr = buf.as_mut_ptr();
        std::mem::forget(buf);
        ptr
    }

    #[no_mangle]
    pub unsafe extern "C" fn wasm_dealloc(ptr: *mut u8, len: usize) {
        let _ = Vec::from_raw_parts(ptr, 0, len);
    }

    #[no_mangle]
    pub extern "C" fn wasm_init_dev_pk() -> u32 {
        let (pk, _vk) = setup_joinsplit_dev();
        let sz = pk.compressed_size() as u32;
        CACHED_PK.with(|c| *c.borrow_mut() = Some(pk));
        sz
    }

    #[no_mangle]
    pub unsafe extern "C" fn wasm_load_pk_compressed(ptr: *const u8, len: usize) -> i32 {
        let slice = std::slice::from_raw_parts(ptr, len);
        match deserialize_pk_compressed(slice) {
            Ok(pk) => {
                CACHED_PK.with(|c| *c.borrow_mut() = Some(pk));
                0
            }
            Err(_) => -5,
        }
    }

    /// Prove any valid `JoinSplit4AryCircuit` encoded in the `4,611 B` binary ABI.
    /// Writes `384 B` (`proof_192 || nf0 || nf1 || cm0 || cm1 || cm2 || pub_hash`) to `out_ptr`.
    /// Returns `0` on success or negative error code on failure.
    #[no_mangle]
    pub unsafe extern "C" fn wasm_prove_joinsplit(
        witness_ptr: *const u8,
        witness_len: usize,
        seed_ptr: *const u8,
        out_ptr: *mut u8,
    ) -> i32 {
        let witness = std::slice::from_raw_parts(witness_ptr, witness_len);
        let seed_slice = std::slice::from_raw_parts(seed_ptr, 32);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_slice);

        let circuit = match decode_joinsplit_witness_bytes(witness) {
            Ok(c) => c,
            Err(code) => return code,
        };
        let pub_in = circuit.public_inputs();
        let pub_hash = pub_in.compute_hash();

        CACHED_PK.with(|c| {
            let guard = c.borrow();
            let Some(pk) = guard.as_ref() else {
                return -1;
            };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let proof = match Groth16::<Bn254>::prove(pk, circuit, &mut rng) {
                Ok(p) => p,
                Err(_) => return -4,
            };
            let wire = solana_export::proof_to_solana_compressed_192(&proof);
            let out = std::slice::from_raw_parts_mut(out_ptr, PROVE_OUTPUT_BYTES);
            out[0..192].copy_from_slice(&wire);
            out[192..224].copy_from_slice(&fr_to_be_bytes(&pub_in.nullifiers[0]));
            out[224..256].copy_from_slice(&fr_to_be_bytes(&pub_in.nullifiers[1]));
            out[256..288].copy_from_slice(&fr_to_be_bytes(&pub_in.out_commitments[0]));
            out[288..320].copy_from_slice(&fr_to_be_bytes(&pub_in.out_commitments[1]));
            out[320..352].copy_from_slice(&fr_to_be_bytes(&pub_in.out_commitments[2]));
            out[352..384].copy_from_slice(&fr_to_be_bytes(&pub_hash));
            0
        })
    }

    /// Compute canonical Circom / Solana `sol_poseidon` BN254 x^5 hash over `arity` (1..=12)
    /// 32-byte BE inputs at `inputs_ptr`, writing 32-byte BE digest to `out_ptr`.
    #[no_mangle]
    pub unsafe extern "C" fn wasm_poseidon_hash(
        arity: u32,
        inputs_ptr: *const u8,
        out_ptr: *mut u8,
    ) -> i32 {
        let n = arity as usize;
        if n == 0 || n > 12 {
            return -2;
        }
        let raw = std::slice::from_raw_parts(inputs_ptr, n * 32);
        let mut frs = Vec::with_capacity(n);
        for i in 0..n {
            let chunk: [u8; 32] = raw[i * 32..(i + 1) * 32].try_into().unwrap();
            let Some(f) = fr_from_be_bytes_strict(&chunk) else {
                return -3;
            };
            frs.push(f);
        }
        let digest = poseidon::poseidon_hash(&frs);
        let out = std::slice::from_raw_parts_mut(out_ptr, 32);
        out.copy_from_slice(&fr_to_be_bytes(&digest));
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{
            build_historical_witness_4ary, compute_subtree_256_root, compute_super_root_4ary,
            zero_hashes_4ary, NUM_LANES,
        },
        note::{compute_note_commitment, derive_asset_id, derive_spend_pk, derive_stealth_owner},
        poseidon::poseidon_hash,
    };

    #[test]
    fn poseidon_matches_solana_poseidon_official_vectors_and_core_zeros() {
        let one = Fr::from(1u64);
        let expected_1 = [
            41, 23, 97, 0, 234, 169, 98, 189, 193, 254, 108, 101, 77, 106, 60, 19, 14, 150, 164,
            209, 22, 139, 51, 132, 139, 137, 125, 197, 2, 130, 1, 51,
        ];
        let expected_4 = [
            5, 50, 253, 67, 110, 25, 199, 14, 81, 32, 150, 148, 217, 194, 21, 37, 9, 55, 146, 27,
            139, 121, 6, 4, 136, 193, 32, 109, 183, 62, 153, 70,
        ];
        assert_eq!(fr_to_be_bytes(&poseidon_hash(&[one])), expected_1);
        assert_eq!(
            fr_to_be_bytes(&poseidon_hash(&[
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64)
            ])),
            expected_4
        );

        let z = zero_hashes_4ary();
        for (h, zh) in z.iter().enumerate() {
            assert_eq!(
                fr_to_be_bytes(zh),
                audren_core::ZERO_HASHES_4ARY[h],
                "ZERO_HASHES_4ARY[{h}] drifted from audren-core"
            );
        }
    }

    #[test]
    fn frozen_circuit_constraint_count_and_witness_abi_roundtrip() {
        let (c, _w, i) = count_constraints(JoinSplit4AryCircuit::empty_for_setup());
        assert_eq!(c, 17_861, "frozen circuit constraint count must stay 17,861");
        assert_eq!(i, 2, "1 constant + 1 public_input_hash");

        let real = JoinSplit4AryCircuit::realistic_benchmark_instance();
        let bytes = encode_joinsplit_witness_bytes(&real);
        let decoded = decode_joinsplit_witness_bytes(&bytes).expect("decode witness");
        assert_eq!(decoded.public_input_hash, real.public_input_hash);
        let cs = ConstraintSystem::<Fr>::new_ref();
        decoded.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn adversarial_soundness_and_historical_truncation() {
        let zeros = zero_hashes_4ary();
        let sk = Fr::from(0xDEAD_BEEF_1234u64);
        let pk = derive_spend_pk(sk);
        let asset_usdc = derive_asset_id(&[0x11; 32]);
        let asset_sol = derive_asset_id(&audren_core::NATIVE_SOL_MINT);

        // Build 300 leaves in lane 3 and verify historical truncation at N_E = 100
        let mut leaves = Vec::with_capacity(300);
        for i in 0..300u64 {
            leaves.push(compute_note_commitment(
                derive_stealth_owner(pk, Fr::from(i + 1)),
                asset_usdc,
                1_000_000 + i,
                Fr::from(i + 999),
            ));
        }
        let sub0_at_100 = compute_subtree_256_root(&leaves[0..256], 100);
        let mut cur = sub0_at_100;
        for h in 4..18 {
            cur = poseidon::poseidon4(cur, zeros[h], zeros[h], zeros[h]);
        }
        let mut lane_roots = [zeros[18]; NUM_LANES];
        lane_roots[3] = cur;
        let super_root = compute_super_root_4ary(&lane_roots);
        let path42 = build_historical_witness_4ary(
            3,
            42,
            &lane_roots,
            100,
            &[],
            &leaves[0..256],
            Some(&leaves[0..256]),
        );
        assert_eq!(path42.compute_root(leaves[42]), super_root);
        assert_eq!(path42.global_leaf_index(), (3u64 << 36) | 42);

        let make_valid = |omit_nf1: bool| {
            JoinSplit4AryCircuit::new_with_options(
                super_root,
                asset_usdc,
                Fr::from(0u64),
                0,
                0,
                Fr::from(77u64),
                omit_nf1,
                [
                    JoinSplitInputWitness {
                        spend_sk: sk,
                        tweak: Fr::from(43u64),
                        asset_id: asset_usdc,
                        amount: 1_000_042,
                        blinding: Fr::from(42 + 999),
                        is_dummy: false,
                        merkle_path: path42.clone(),
                    },
                    JoinSplitInputWitness {
                        spend_sk: sk,
                        tweak: Fr::from(0u64),
                        asset_id: asset_usdc,
                        amount: 0,
                        blinding: Fr::from(888u64),
                        is_dummy: true,
                        merkle_path: MerklePath4Ary::default(),
                    },
                ],
                [
                    JoinSplitOutputWitness {
                        stealth_owner: derive_stealth_owner(pk, Fr::from(500u64)),
                        asset_id: asset_usdc,
                        amount: 1_000_042,
                        blinding: Fr::from(501u64),
                    },
                    JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(502u64)),
                    JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(503u64)),
                ],
            )
        };

        let is_sat = |c: JoinSplit4AryCircuit| -> bool {
            let cs = ConstraintSystem::<Fr>::new_ref();
            c.generate_constraints(cs.clone()).unwrap();
            cs.is_satisfied().unwrap()
        };

        assert!(is_sat(make_valid(false)));
        assert!(is_sat(make_valid(true)));

        // Attack 1: Inflate output amount (+1)
        let mut a1 = make_valid(false);
        a1.outputs[0].amount += 1;
        a1.public_input_hash = a1.public_inputs().compute_hash();
        assert!(!is_sat(a1), "value inflation must be rejected");

        // Attack 2: Cross-asset public withdraw mismatch
        let mut a2 = make_valid(false);
        a2.outputs[0].amount = 0;
        a2.public_amount_out = 1_000_042;
        a2.public_asset_id = asset_sol;
        a2.public_input_hash = a2.public_inputs().compute_hash();
        assert!(!is_sat(a2), "cross-asset public exit must be rejected");

        // Attack 3: Non-zero dummy input
        let mut a3 = make_valid(false);
        a3.inputs[1].amount = 1;
        a3.outputs[0].amount += 1;
        a3.public_input_hash = a3.public_inputs().compute_hash();
        assert!(!is_sat(a3), "non-zero dummy input must be rejected");

        // Attack 4: Economy omit_nf1 on real non-dummy input 1
        let mut a4 = make_valid(true);
        a4.inputs[1] = a4.inputs[0].clone();
        a4.outputs[0].amount *= 2;
        a4.public_input_hash = a4.public_inputs().compute_hash();
        assert!(!is_sat(a4), "omit_nf1 on real input must be rejected");

        // Attack 5: Same note double-spent in slot 0 and slot 1
        let mut a5 = make_valid(false);
        a5.inputs[1] = a5.inputs[0].clone();
        a5.outputs[0].amount *= 2;
        a5.public_input_hash = a5.public_inputs().compute_hash();
        assert!(!is_sat(a5), "duplicate nullifier spend must be rejected");

        // Attack 6: Sentinel tx_asset_id == 0
        let mut a6 = JoinSplit4AryCircuit::empty_for_setup();
        a6.tx_asset_id = Fr::from(0u64);
        a6.inputs[0].asset_id = Fr::from(0u64);
        a6.inputs[1].asset_id = Fr::from(0u64);
        for o in &mut a6.outputs {
            o.asset_id = Fr::from(0u64);
        }
        a6.public_input_hash = a6.public_inputs().compute_hash();
        assert!(!is_sat(a6), "tx_asset_id == 0 must be rejected");
    }
}
