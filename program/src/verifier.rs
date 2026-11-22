//! Groth16 BN254 on-chain verifier using `groth16-solana 0.3.1` (`alt_bn128` syscalls).
//!
//! Accepts compact **192-byte** proofs (`(-A)_compressed[32] || B_be[128] || C_compressed[32]`)
//! verified against the single minimal frozen `VK_JOINSPLIT_DEFAULT` (`vk_id = 0`).

use groth16_solana::{
    decompression::decompress_g1,
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::ProgramResult;

use crate::{
    state::{err, AudrenError, GROTH16_PROOF_LEN, VK_ID_DEFAULT},
    vk_generated::VK_JOINSPLIT_DEFAULT,
};

#[inline(never)]
pub fn verify_joinsplit_proof_192(
    vk_id: u8,
    proof_192: &[u8; GROTH16_PROOF_LEN],
    public_input_hash: [u8; 32],
) -> ProgramResult {
    let vk: &Groth16Verifyingkey = match vk_id {
        VK_ID_DEFAULT => &VK_JOINSPLIT_DEFAULT,
        _ => return Err(err(AudrenError::InvalidVkId)),
    };

    let a_comp: &[u8; 32] = proof_192[0..32].try_into().unwrap();
    let b_be: &[u8; 128] = proof_192[32..160].try_into().unwrap();
    let c_comp: &[u8; 32] = proof_192[160..192].try_into().unwrap();

    let proof_a =
        decompress_g1(a_comp).map_err(|_| err(AudrenError::ProofVerificationFailed))?;
    let proof_c =
        decompress_g1(c_comp).map_err(|_| err(AudrenError::ProofVerificationFailed))?;
    let pub_inputs = [public_input_hash];

    let mut verifier = Groth16Verifier::new(&proof_a, b_be, &proof_c, &pub_inputs, vk)
        .map_err(|_| err(AudrenError::ProofVerificationFailed))?;
    verifier
        .verify()
        .map_err(|_| err(AudrenError::ProofVerificationFailed))?;
    Ok(())
}
