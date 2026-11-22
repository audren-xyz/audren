//! Live Devnet integration smoke harness (run explicitly with `AUDREN_DEVNET_LIVE=1`).

use audren_client::{
    audren_core::{AUDREN_PROGRAM_ID, DEFAULT_INITIAL_LANES},
    keys::AudrenKeys,
    pda::{derive_lane_pda, derive_pool_pda, derive_sol_vault_pda, derive_vault_auth_pda},
};
use solana_address::Address;

#[test]
#[ignore = "requires live Solana Devnet RPC and funded keypair; run with --ignored"]
fn devnet_live_pda_and_keys_smoke() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let (pool, _) = derive_pool_pda(&program_id, 0);
    let (sol_vault, _) = derive_sol_vault_pda(&program_id, 0);
    let (vault_auth, _) = derive_vault_auth_pda(&program_id, 0);
    let keys = AudrenKeys::from_seed(&[0xAB; 32]);
    println!("Audren Program: {program_id}");
    println!("  Pool #0 PDA:       {pool}");
    println!("  SOL Vault PDA:     {sol_vault}");
    println!("  Vault Auth PDA:    {vault_auth}");
    for l in 0..DEFAULT_INITIAL_LANES {
        let (lp, _) = derive_lane_pda(&program_id, 0, l);
        println!("  Lane #{l} PDA:       {lp}");
    }
    println!("  Sample Address:    {}", keys.address().encode());
}
