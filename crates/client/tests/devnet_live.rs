//! Offline Pool #0 PDA & key derivation smoke check for Devnet/Mainnet deployments.

use audren_client::{
    audren_core::{AUDREN_PROGRAM_ID, DEFAULT_INITIAL_LANES},
    keys::AudrenKeys,
    pda::{derive_lane_pda, derive_pool_pda, derive_sol_vault_pda, derive_vault_auth_pda},
};
use solana_address::Address;

#[test]
fn pool0_pda_and_keys_smoke() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let (pool, _) = derive_pool_pda(&program_id, 0);
    let (sol_vault, _) = derive_sol_vault_pda(&program_id, 0);
    let (vault_auth, _) = derive_vault_auth_pda(&program_id, 0);
    assert_eq!(pool.to_string(), "8CN7uxRdQGjuAaZQVVcHRZbptSzvgfUv7tg8EarLHztF");
    assert_eq!(sol_vault.to_string(), "CEpjPxvw68qVqCGAHmpYxVk6XRBqf6asLpiri8wFiD7K");
    assert_eq!(vault_auth.to_string(), "53H7qJDZxmFbEcBpCJ8GE3LNTL3zjdJwCjwWRKkXE8J7");
    let keys = AudrenKeys::from_seed(&[0xAB; 32]);
    assert!(keys.address().encode().starts_with("aud1"));
    for l in 0..DEFAULT_INITIAL_LANES {
        let (lp, _) = derive_lane_pda(&program_id, 0, l);
        assert_ne!(lp, pool);
    }
}
