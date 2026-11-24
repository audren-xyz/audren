//! Offline Pool #0 PDA & key derivation smoke check for Devnet/Mainnet deployments.

use audren_client::{
    audren_core::{AUDREN_PROGRAM_ID, DEFAULT_INITIAL_LANES},
    keys::{AudrenAddress, AudrenKeys},
    pda::{derive_lane_pda, derive_pool_pda, derive_roots_pda, derive_vault_auth_pda},
};
use solana_address::Address;

#[test]
fn pool0_pda_and_keys_smoke() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let (pool, pool_bump) = derive_pool_pda(&program_id, 0);
    let (vault_auth, va_bump) = derive_vault_auth_pda(&program_id, 0);
    let (roots, roots_bump) = derive_roots_pda(&program_id, 0);
    assert_eq!(pool.to_string(), "5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G");
    assert_eq!(pool_bump, 255);
    assert_eq!(vault_auth.to_string(), "3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF");
    assert_eq!(va_bump, 255);
    assert_eq!(roots.to_string(), "249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7");
    assert_eq!(roots_bump, 254);
    let keys = AudrenKeys::from_seed(&[0xAB; 32]);
    let encoded = keys.address().encode().unwrap();
    assert!(encoded.starts_with("aud1"));
    assert_eq!(encoded.len(), 114);
    assert_eq!(AudrenAddress::decode(&encoded).unwrap(), keys.address());
    for l in 0..DEFAULT_INITIAL_LANES {
        let (lp, _) = derive_lane_pda(&program_id, 0, l);
        assert_ne!(lp, pool);
    }
}
