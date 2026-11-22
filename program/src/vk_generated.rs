//! Auto-generated VerifyingKey for Audren `JoinSplit4AryCircuit` (`vk_id = 0`).
//!
//! Provenance: Perpetual Powers of Tau (powersOfTau28_hez_final_15.ptau, 71+ contributors) + Audren BGM17 Phase-2 Ceremony (drand Quicknet #34194203 & Solana Mainnet slot 472705896)
//! ProvingKey compressed SHA-256: `2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4`
//! Phase 1: Official Hermez/PSE Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`,
//!          71+ public contributors, BLAKE2b-512 `982372c8...69ae6e`, SHA-256 `3ef2ecc5...9e7f`).
//! Phase 2: BGM17 Groth16 MPC ceremony (`ceremony/transcript.json`, verifiable via
//!          `cargo run -p audren-circuits --release --bin ceremony -- verify`).

#[allow(dead_code)]
pub const VK_PROVENANCE: &str = "Perpetual Powers of Tau (powersOfTau28_hez_final_15.ptau, 71+ contributors) + Audren BGM17 Phase-2 Ceremony (drand Quicknet #34194203 & Solana Mainnet slot 472705896)";
#[allow(dead_code)]
pub const PK_COMPRESSED_SHA256: &str = "2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4";

pub const VK_JOINSPLIT_DEFAULT_IC: &[[u8; 64]] = &[
    [4u8, 72u8, 223u8, 254u8, 35u8, 47u8, 89u8, 140u8, 173u8, 62u8, 248u8, 8u8, 235u8, 126u8, 82u8, 174u8, 127u8, 226u8, 128u8, 17u8, 87u8, 39u8, 251u8, 142u8, 34u8, 215u8, 170u8, 102u8, 211u8, 245u8, 228u8, 177u8, 42u8, 61u8, 112u8, 160u8, 121u8, 130u8, 9u8, 214u8, 91u8, 171u8, 35u8, 170u8, 189u8, 13u8, 150u8, 143u8, 193u8, 233u8, 127u8, 198u8, 62u8, 168u8, 177u8, 180u8, 167u8, 184u8, 222u8, 74u8, 175u8, 226u8, 19u8, 75u8],
    [1u8, 121u8, 179u8, 220u8, 240u8, 77u8, 13u8, 4u8, 136u8, 177u8, 33u8, 96u8, 126u8, 154u8, 233u8, 80u8, 174u8, 214u8, 38u8, 209u8, 7u8, 56u8, 74u8, 44u8, 138u8, 34u8, 219u8, 229u8, 127u8, 226u8, 34u8, 199u8, 32u8, 222u8, 83u8, 74u8, 131u8, 77u8, 186u8, 74u8, 249u8, 198u8, 115u8, 30u8, 50u8, 136u8, 219u8, 151u8, 36u8, 63u8, 32u8, 149u8, 245u8, 104u8, 212u8, 26u8, 64u8, 48u8, 40u8, 135u8, 4u8, 0u8, 6u8, 243u8],
];

pub const VK_JOINSPLIT_DEFAULT: groth16_solana::groth16::Groth16Verifyingkey<'static> = groth16_solana::groth16::Groth16Verifyingkey {
    nr_pubinputs: 1,
    vk_alpha_g1: [45u8, 77u8, 154u8, 167u8, 227u8, 2u8, 217u8, 223u8, 65u8, 116u8, 157u8, 85u8, 7u8, 148u8, 157u8, 5u8, 219u8, 234u8, 51u8, 251u8, 177u8, 108u8, 100u8, 59u8, 34u8, 245u8, 153u8, 162u8, 190u8, 109u8, 242u8, 226u8, 20u8, 190u8, 221u8, 80u8, 60u8, 55u8, 206u8, 176u8, 97u8, 216u8, 236u8, 96u8, 32u8, 159u8, 227u8, 69u8, 206u8, 137u8, 131u8, 10u8, 25u8, 35u8, 3u8, 1u8, 240u8, 118u8, 202u8, 255u8, 0u8, 77u8, 25u8, 38u8],
    vk_beta_g2: [9u8, 103u8, 3u8, 47u8, 203u8, 247u8, 118u8, 209u8, 175u8, 201u8, 133u8, 248u8, 136u8, 119u8, 241u8, 130u8, 211u8, 132u8, 128u8, 166u8, 83u8, 242u8, 222u8, 202u8, 169u8, 121u8, 76u8, 188u8, 59u8, 243u8, 6u8, 12u8, 14u8, 24u8, 120u8, 71u8, 173u8, 76u8, 121u8, 131u8, 116u8, 208u8, 214u8, 115u8, 43u8, 245u8, 1u8, 132u8, 125u8, 214u8, 139u8, 192u8, 224u8, 113u8, 36u8, 30u8, 2u8, 19u8, 188u8, 127u8, 193u8, 61u8, 183u8, 171u8, 48u8, 76u8, 251u8, 209u8, 224u8, 138u8, 112u8, 74u8, 153u8, 245u8, 232u8, 71u8, 217u8, 63u8, 140u8, 60u8, 170u8, 253u8, 222u8, 196u8, 107u8, 122u8, 13u8, 55u8, 157u8, 166u8, 154u8, 77u8, 17u8, 35u8, 70u8, 167u8, 23u8, 57u8, 193u8, 177u8, 164u8, 87u8, 168u8, 199u8, 49u8, 49u8, 35u8, 210u8, 77u8, 47u8, 145u8, 146u8, 248u8, 150u8, 183u8, 198u8, 62u8, 234u8, 5u8, 169u8, 213u8, 127u8, 6u8, 84u8, 122u8, 208u8, 206u8, 200u8],
    vk_gamma_g2: [25u8, 142u8, 147u8, 147u8, 146u8, 13u8, 72u8, 58u8, 114u8, 96u8, 191u8, 183u8, 49u8, 251u8, 93u8, 37u8, 241u8, 170u8, 73u8, 51u8, 53u8, 169u8, 231u8, 18u8, 151u8, 228u8, 133u8, 183u8, 174u8, 243u8, 18u8, 194u8, 24u8, 0u8, 222u8, 239u8, 18u8, 31u8, 30u8, 118u8, 66u8, 106u8, 0u8, 102u8, 94u8, 92u8, 68u8, 121u8, 103u8, 67u8, 34u8, 212u8, 247u8, 94u8, 218u8, 221u8, 70u8, 222u8, 189u8, 92u8, 217u8, 146u8, 246u8, 237u8, 9u8, 6u8, 137u8, 208u8, 88u8, 95u8, 240u8, 117u8, 236u8, 158u8, 153u8, 173u8, 105u8, 12u8, 51u8, 149u8, 188u8, 75u8, 49u8, 51u8, 112u8, 179u8, 142u8, 243u8, 85u8, 172u8, 218u8, 220u8, 209u8, 34u8, 151u8, 91u8, 18u8, 200u8, 94u8, 165u8, 219u8, 140u8, 109u8, 235u8, 74u8, 171u8, 113u8, 128u8, 141u8, 203u8, 64u8, 143u8, 227u8, 209u8, 231u8, 105u8, 12u8, 67u8, 211u8, 123u8, 76u8, 230u8, 204u8, 1u8, 102u8, 250u8, 125u8, 170u8],
    vk_delta_g2: [40u8, 10u8, 127u8, 15u8, 58u8, 6u8, 84u8, 101u8, 18u8, 14u8, 238u8, 0u8, 160u8, 113u8, 27u8, 138u8, 224u8, 193u8, 114u8, 17u8, 33u8, 167u8, 10u8, 53u8, 107u8, 255u8, 117u8, 156u8, 177u8, 190u8, 227u8, 78u8, 7u8, 116u8, 127u8, 183u8, 131u8, 192u8, 35u8, 97u8, 48u8, 34u8, 226u8, 27u8, 90u8, 213u8, 26u8, 204u8, 34u8, 5u8, 116u8, 208u8, 140u8, 156u8, 194u8, 154u8, 208u8, 43u8, 174u8, 120u8, 203u8, 229u8, 251u8, 204u8, 44u8, 24u8, 210u8, 24u8, 208u8, 134u8, 51u8, 192u8, 144u8, 3u8, 56u8, 15u8, 164u8, 191u8, 110u8, 204u8, 206u8, 227u8, 238u8, 137u8, 24u8, 70u8, 103u8, 244u8, 244u8, 131u8, 97u8, 93u8, 30u8, 190u8, 144u8, 253u8, 6u8, 107u8, 73u8, 5u8, 195u8, 14u8, 182u8, 114u8, 19u8, 16u8, 227u8, 5u8, 49u8, 207u8, 142u8, 13u8, 139u8, 185u8, 9u8, 109u8, 98u8, 41u8, 66u8, 77u8, 143u8, 53u8, 177u8, 140u8, 248u8, 124u8, 165u8, 65u8],
    vk_ic: VK_JOINSPLIT_DEFAULT_IC,
    vk_commitment: None,
};
