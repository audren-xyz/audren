use std::path::PathBuf;

use ark_bn254::Fr;
use audren_circuits::{
    compressed_pk_size, count_constraints,
    joinsplit::JoinSplit4AryCircuit,
    poseidon::fr_to_be_bytes,
    serialize_pk_compressed, setup_joinsplit_dev,
    solana_export::render_solana_vk_const,
};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use sha2::{Digest, Sha256};

fn dump_ts_poseidon(out_path: &str) {
    let mut out = String::new();
    out.push_str("// Auto-generated exact Circom / Solana `sol_poseidon` BN254 x^5 constants.\n");
    out.push_str("// Generated directly from `light-poseidon` (`crates/audren-circuits/src/bin/gen_vk.rs`).\n\n");
    out.push_str("export interface PoseidonParams {\n");
    out.push_str("  readonly width: number;\n");
    out.push_str("  readonly fullRounds: number;\n");
    out.push_str("  readonly partialRounds: number;\n");
    out.push_str("  readonly ark: readonly bigint[];\n");
    out.push_str("  readonly mds: readonly (readonly bigint[])[];\n");
    out.push_str("}\n\n");
    out.push_str("export const POSEIDON_PARAMS: Record<number, PoseidonParams> = {\n");
    for width in 2u8..=6u8 {
        let p = get_poseidon_parameters::<Fr>(width).expect("params");
        let hex_bi = |f: &Fr| -> String {
            let b = fr_to_be_bytes(f);
            let mut s = String::from("0x");
            for byte in b {
                s.push_str(&format!("{byte:02x}"));
            }
            s.push('n');
            s
        };
        out.push_str(&format!("  {width}: {{\n"));
        out.push_str(&format!("    width: {width},\n"));
        out.push_str(&format!("    fullRounds: {},\n", p.full_rounds));
        out.push_str(&format!("    partialRounds: {},\n", p.partial_rounds));
        out.push_str("    ark: [\n");
        for c in &p.ark {
            out.push_str(&format!("      {},\n", hex_bi(c)));
        }
        out.push_str("    ],\n");
        out.push_str("    mds: [\n");
        for row in &p.mds {
            out.push_str("      [");
            for (i, c) in row.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&hex_bi(c));
            }
            out.push_str("],\n");
        }
        out.push_str("    ],\n");
        out.push_str("  },\n");
    }
    out.push_str("};\n");
    std::fs::write(out_path, out).expect("write poseidon-constants.ts");
    println!("Wrote Circom BN254 Poseidon constants -> {out_path}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--dump-ts-poseidon") {
        let out_path = args
            .get(2)
            .map(String::as_str)
            .unwrap_or("packages/sdk/src/poseidon-constants.ts");
        dump_ts_poseidon(out_path);
        return;
    }

    let out_vk = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "program/src/vk_generated.rs".to_string());
    let out_pk = args.get(2).cloned();

    let (c, w, i) = count_constraints(JoinSplit4AryCircuit::empty_for_setup());
    println!("JoinSplit4AryCircuit: {c} constraints | {w} witnesses | {i} instance vars");

    let (pk, vk) = setup_joinsplit_dev();
    let pk_bytes = serialize_pk_compressed(&pk);
    let pk_sha: [u8; 32] = Sha256::digest(&pk_bytes).into();
    let pk_sha_hex: String = pk_sha.iter().map(|b| format!("{b:02x}")).collect();

    let mut src = String::new();
    src.push_str("//! Auto-generated VerifyingKey for Audren `JoinSplit4AryCircuit` (`vk_id = 0`).\n");
    src.push_str("//! Provenance: DEV_DETERMINISTIC_VK (replace with public Phase-2 MPC ceremony artifact before Mainnet).\n\n");
    src.push_str("#[allow(dead_code)]\n");
    src.push_str(&format!(
        "pub const VK_PROVENANCE: &str = \"DEV_DETERMINISTIC_VK\";\n"
    ));
    src.push_str("#[allow(dead_code)]\n");
    src.push_str(&format!(
        "pub const PK_COMPRESSED_SHA256: &str = \"{pk_sha_hex}\";\n\n"
    ));
    src.push_str(&render_solana_vk_const("VK_JOINSPLIT_DEFAULT", &vk));

    std::fs::write(&out_vk, src).expect("write vk_generated.rs");
    println!(
        "Wrote {out_vk} | PK compressed={} B ({:.2} MB) | sha256={pk_sha_hex}",
        compressed_pk_size(&pk),
        pk_bytes.len() as f64 / 1_048_576.0
    );

    if let Some(pk_path) = out_pk {
        let p = PathBuf::from(pk_path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&p, &pk_bytes).expect("write compressed pk");
        println!("Wrote compressed PK -> {}", p.display());
    }
}
