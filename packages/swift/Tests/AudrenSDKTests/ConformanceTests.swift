import Foundation
import XCTest
@testable import AudrenSDK

private struct KeyVector: Decodable {
    let seed_hex: String
    let spend_sk_hex: String
    let spend_pk_hex: String
    let nk_hex: String
    let view_sk_hex: String
    let view_pk_hex: String
    let address: String
}

private struct DefiSessionVector: Decodable {
    let session_index: UInt32
    let secret_seed_hex: String
    let pubkey_b58: String
}

private struct PdaEntry: Decodable {
    let address: String
    let bump: UInt8
}

private struct PdaVectors: Decodable {
    let pool_id: UInt32
    let lane_id: UInt8
    let page_seq: UInt64
    let slot_idx: UInt16
    let shard_id: UInt8
    let nullifier_hex: String
    let pool: PdaEntry
    let vault_auth: PdaEntry
    let lane: PdaEntry
    let lane_rent: PdaEntry
    let subtree: PdaEntry
    let subroot: PdaEntry
    let memo: PdaEntry
    let nf_page: PdaEntry
    let checkpoint: PdaEntry
    let nullifier: PdaEntry
    let escrow: PdaEntry
    let unwrap: PdaEntry
}

private struct AssetIdVectors: Decodable {
    let wsol_asset_id_hex: String
    let usdc_mint_b58: String
    let usdc_asset_id_hex: String
}

private struct MemoVector: Decodable {
    let eph_secret_hex: String
    let amount: UInt64
    let mint_hex: String
    let payment_id_hex: String
    let tweak_hex: String
    let blinding_hex: String
    let stealth_owner_hex: String
    let commitment_hex: String
    let memo_106_hex: String
    let dyn_eph_secret_hex: String
    let dyn_tweak_hex: String
    let dyn_blinding_hex: String
    let dyn_head_34_hex: String
    let dyn_mask_72_hex: String
    let dyn_amount: UInt64
    let dyn_mint_hex: String
    let dyn_commitment_hex: String
    let dyn_stamped_memo_106_hex: String
}

private struct LowOrderX25519Vectors: Decodable {
    let all_zero_epk_hex: String
    let order_8_epk_hex: String
}

private struct SelectiveDisclosureVector: Decodable {
    let pool_id: UInt32
    let lane_id: UInt8
    let leaf_index: UInt64
    let stealth_owner: [UInt8]
    let mint: [UInt8]
    let amount: UInt64
    let blinding: [UInt8]
    let commitment: [UInt8]
}

private struct CtxHashVectors: Decodable {
    let transact_private_ctx_hash_hex: String
    let transact_wsol_unwrap_ctx_hash_hex: String
    let exec_fee_on_output_ctx_hash_hex: String
}

private struct Groth16Vector: Decodable {
    let vk_id: UInt8
    let super_root_hex: String
    let out0_stealth_owner_hex: String
    let out1_stealth_owner_hex: String
    let nf0_hex: String
    let nf1_hex: String
    let cm0_hex: String
    let cm1_hex: String
    let cm2_hex: String
    let public_input_hash_hex: String
    let proof_192_hex: String
}

private struct PoolStateVector: Decodable {
    let raw_hex: String
    let pool_id: UInt32
    let active_lanes: UInt8
    let ckpt_interval: UInt64
    let max_ckpt_age: UInt64
    let note_rent_fee: UInt64
    let nf_rent_fee: UInt64
    let paused: Bool
    let pending_authority_b58: String
}

private struct ConformanceVectors: Decodable {
    let protocol_version: UInt8
    let program_id: String
    let alice: KeyVector
    let alice_sub1: KeyVector
    let bob: KeyVector
    let defi_session_0: DefiSessionVector
    let defi_session_3: DefiSessionVector
    let asset_ids: AssetIdVectors
    let pdas: PdaVectors
    let memo: MemoVector
    let low_order_x25519: LowOrderX25519Vectors
    let selective_disclosure: SelectiveDisclosureVector
    let ctx_hashes: CtxHashVectors
    let groth16: Groth16Vector
    let pool_state: PoolStateVector
    let checkpoint_raw_hex: String
}

private func hexToData(_ hex: String) -> Data {
    var data = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        data.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return data
}

private func dataToHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func loadVectors() throws -> ConformanceVectors {
    let testFile = URL(fileURLWithPath: #filePath)
    let repoRoot = testFile
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let url = repoRoot.appendingPathComponent("spec/test-vectors.json")
    return try JSONDecoder().decode(ConformanceVectors.self, from: Data(contentsOf: url))
}

final class ConformanceTests: XCTestCase {
    func testConformanceVectors() throws {
        let v = try loadVectors()

        XCTAssertEqual(protocolVersion(), v.protocol_version)
        XCTAssertEqual(canonicalProgramId(), v.program_id)

        // 1. Keys, Subaccounts, FVK, BIP-350 Bech32m aud1 Address, DeFi Sessions
        let aliceSeed = hexToData(v.alice.seed_hex)
        let alice = try deriveKeysFromSeed(seed: aliceSeed)
        XCTAssertEqual(dataToHex(alice.spendSk), v.alice.spend_sk_hex)
        XCTAssertEqual(dataToHex(alice.spendPk), v.alice.spend_pk_hex)
        XCTAssertEqual(dataToHex(alice.nk), v.alice.nk_hex)
        XCTAssertEqual(dataToHex(alice.viewSk), v.alice.view_sk_hex)
        XCTAssertEqual(dataToHex(alice.viewPk), v.alice.view_pk_hex)
        XCTAssertEqual(alice.address, v.alice.address)

        let decoded = try decodeAudrenAddress(encoded: alice.address)
        XCTAssertEqual(dataToHex(decoded[0]), v.alice.spend_pk_hex)
        XCTAssertEqual(dataToHex(decoded[1]), v.alice.view_pk_hex)

        let sub1 = try deriveSubaccountKeys(seed: aliceSeed, accountIndex: 1)
        XCTAssertEqual(sub1.address, v.alice_sub1.address)

        let fvk = try exportFullViewingKey(seed: aliceSeed)
        XCTAssertEqual(dataToHex(fvk.nk), v.alice.nk_hex)

        let sess0 = try deriveDefiSessionKeypair(seed: aliceSeed, sessionIndex: 0)
        XCTAssertEqual(sess0.pubkeyB58, v.defi_session_0.pubkey_b58)
        let sess3 = try deriveDefiSessionKeypair(seed: aliceSeed, sessionIndex: 3)
        XCTAssertEqual(sess3.pubkeyB58, v.defi_session_3.pubkey_b58)

        // 2. Asset ID & 12 Canonical v1 PDAs
        let wsolMint = hexToData(v.memo.mint_hex)
        XCTAssertEqual(
            dataToHex(try deriveAssetIdBytes(mintBytes: wsolMint)),
            v.asset_ids.wsol_asset_id_hex
        )
        let pid = v.program_id
        let nf = hexToData(v.pdas.nullifier_hex)
        XCTAssertEqual(try derivePoolPda(programId: pid, poolId: v.pdas.pool_id).address, v.pdas.pool.address)
        XCTAssertEqual(try deriveVaultAuthPda(programId: pid, poolId: v.pdas.pool_id).address, v.pdas.vault_auth.address)
        XCTAssertEqual(try deriveLanePda(programId: pid, poolId: v.pdas.pool_id, laneId: v.pdas.lane_id).address, v.pdas.lane.address)
        XCTAssertEqual(try deriveLaneRentPda(programId: pid, poolId: v.pdas.pool_id, laneId: v.pdas.lane_id).address, v.pdas.lane_rent.address)
        XCTAssertEqual(try deriveSubtreePda(programId: pid, poolId: v.pdas.pool_id, laneId: v.pdas.lane_id, pageSeq: v.pdas.page_seq).address, v.pdas.subtree.address)
        XCTAssertEqual(try deriveSubrootPda(programId: pid, poolId: v.pdas.pool_id, laneId: v.pdas.lane_id, rootPageSeq: v.pdas.page_seq).address, v.pdas.subroot.address)
        XCTAssertEqual(try deriveMemoPda(programId: pid, poolId: v.pdas.pool_id, laneId: v.pdas.lane_id, pageSeq: v.pdas.page_seq).address, v.pdas.memo.address)
        XCTAssertEqual(try deriveNfPagePda(programId: pid, poolId: v.pdas.pool_id, laneId: v.pdas.lane_id, pageSeq: v.pdas.page_seq).address, v.pdas.nf_page.address)
        XCTAssertEqual(try deriveCheckpointPda(programId: pid, poolId: v.pdas.pool_id, slotIdx: v.pdas.slot_idx).address, v.pdas.checkpoint.address)
        XCTAssertEqual(try deriveNullifierPda(programId: pid, poolId: v.pdas.pool_id, nullifier: nf).address, v.pdas.nullifier.address)
        XCTAssertEqual(try deriveEscrowPda(programId: pid, poolId: v.pdas.pool_id, shardId: v.pdas.shard_id).address, v.pdas.escrow.address)
        XCTAssertEqual(try deriveUnwrapPda(programId: pid, poolId: v.pdas.pool_id, nf0: nf).address, v.pdas.unwrap.address)

        // 3. Versioned 106 B Memo Crypto + FVK Commitment Verify + Low-Order X25519 + Mode 1 Selective Disclosure
        let paymentId = hexToData(v.memo.payment_id_hex)
        let enc = try encryptNoteMemo(
            recipientSpendPk: alice.spendPk,
            recipientViewPk: alice.viewPk,
            ephSecret: hexToData(v.memo.eph_secret_hex),
            amount: v.memo.amount,
            mint: wsolMint,
            paymentId: paymentId
        )
        XCTAssertEqual(dataToHex(enc.memo106), v.memo.memo_106_hex)
        XCTAssertEqual(dataToHex(enc.commitment), v.memo.commitment_hex)

        let dec = try decryptAndVerifyMemoEntry(fvk: fvk, memo106: enc.memo106, onchainCommitment: enc.commitment)
        XCTAssertNotNil(dec)
        XCTAssertEqual(dec?.amount, v.memo.amount)
        XCTAssertEqual(dec?.paymentId, paymentId)

        XCTAssertFalse(try checkMemoViewTag(fvk: fvk, viewTag: Data([0, 0]), epk: hexToData(v.low_order_x25519.all_zero_epk_hex)))
        XCTAssertFalse(try checkMemoViewTag(fvk: fvk, viewTag: Data([0, 0]), epk: hexToData(v.low_order_x25519.order_8_epk_hex)))

        let dynM = try prepareDynamicSwapMemo(
            recipientViewPk: hexToData(v.bob.view_pk_hex),
            ephSecret: hexToData(v.memo.dyn_eph_secret_hex)
        )
        XCTAssertEqual(dataToHex(dynM.dynHead34), v.memo.dyn_head_34_hex)
        XCTAssertEqual(dataToHex(dynM.dynMask72), v.memo.dyn_mask_72_hex)

        let sd = FfiSelectiveDisclosureProof(
            poolId: v.selective_disclosure.pool_id,
            laneId: v.selective_disclosure.lane_id,
            leafIndex: v.selective_disclosure.leaf_index,
            stealthOwner: Data(v.selective_disclosure.stealth_owner),
            mint: Data(v.selective_disclosure.mint),
            amount: v.selective_disclosure.amount,
            blinding: Data(v.selective_disclosure.blinding),
            commitment: Data(v.selective_disclosure.commitment)
        )
        XCTAssertTrue(try verifySelectiveDisclosureProof(proof: sd, onchainSubtreeLeaf: enc.commitment))

        // 4. Context Hash & Account Decoders
        let ctxPriv = try computeTransactCtxHashFfi(params: FfiTransactCtxHashParams(
            programId: pid,
            poolId: 0,
            vkId: 0,
            outLaneId: 2,
            outputMask: 0b111,
            assetMode: 0,
            unwrapWsol: false,
            recipient: nil,
            relayerFeeRecipient: nil,
            publicAssetId: Data(repeating: 0, count: 32),
            publicAmountOut: 0,
            relayerFeeAmount: 0,
            memosBytes: enc.memo106
        ))
        XCTAssertEqual(dataToHex(ctxPriv), v.ctx_hashes.transact_private_ctx_hash_hex)

        let ps = try decodePoolStateAccount(data: hexToData(v.pool_state.raw_hex))
        XCTAssertEqual(ps.activeLanes, v.pool_state.active_lanes)
        XCTAssertEqual(ps.ckptInterval, v.pool_state.ckpt_interval)
        XCTAssertEqual(ps.pendingAuthorityB58, v.pool_state.pending_authority_b58)

        let ck = try decodeRootCheckpointAccount(data: hexToData(v.checkpoint_raw_hex))
        XCTAssertEqual(ck.slotIdx, 13)
        XCTAssertEqual(ck.laneCounts[2], 6)
        XCTAssertEqual(defaultRelayUrl(), "https://relay.audren.xyz")
        XCTAssertFalse(jupiterCpiExcludedDexes().isEmpty)

        // 5. Native BN254 Groth16 proving via `proveJoinsplitWitnessBytes`
        let zeroHashes = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0532fd436e19c70e51209694d9c215250937921b8b79060488c1206db73e9946",
            "1ea8dbbca1ca3a574b1b871aad1e8bc47571c7e11a99a6fb25f3f19d4bfad32c",
            "1b98ec5a992cd3688e655aef8674386f4e84f0a442eaab4840427e359c214dd2",
            "0fd83a3939005974d559c13c652a31942ffd61cab9a038e04239af96cafaee14",
            "11eb54967ae25ce42205223461cda9dbb1a1811db38b71e404d1fd94c9627777",
            "1c682a99981cf10a215d2788721e0ca060ddc0932cbb04c903eee3bd899dcfc0",
            "2b3de1ae8e72d64a5cb03934061e3fd03789273f370e32d576ae54b4cbeca719",
            "1b64ed0dc55f80f1f3da256b451baf16110fc268311a13fe903f87945b734861",
            "06efb4c4a55b0225fd1088d357b2432f422b0593015c57980e373ecef9029c72",
            "262138dff44f5352d2d7ec48461c771444a6c00c761a3263735d0a99143a51f1",
            "07ea118d86ace14a8eaa26fc18b36fefe7d5f5b00e0eb9ebfd1c88f37131c178",
            "0c2a4af81a2cd78159ce2f3d7ee05367fc5b3c3e1becea2a86d1e66dd27ffb7f",
            "1a953a710c22f79c369c976fc9981ffdbfe236695297fec65886e645e6fa2884",
            "16b0c5e286286eb6c4774ad6292b4f0bdc5b36cb7890b27544268892ae255e0d",
            "2dd7186449cc82702fb8f2d7fa86e0095263f8afb521e1976f499e67a0d7cbb8",
            "151399c724e17408a7a43cdadba2fc000da9339c56e4d49c6cdee6c4356fbc68",
            "1905d56dc6be6157b64b80d21a207b96e862aea4b68f4674ce4c1b7db4a8bc2e",
            "16d33ae1e54afb1453fc544206899ddf3e1a5bdc7f6d8993550aa6876a380319",
            "16e195c570f224cc86219527096fa55516cc9ee1b96764dd263db0884983fdaf",
        ]
        func u64Le(_ x: UInt64) -> Data {
            var le = x.littleEndian
            return Data(bytes: &le, count: 8)
        }
        func u64Be32(_ x: UInt64) -> Data {
            var be = x.bigEndian
            return Data(repeating: 0, count: 24) + Data(bytes: &be, count: 8)
        }
        let wsolAsset = hexToData(v.asset_ids.wsol_asset_id_hex)
        var w = Data(capacity: 4611)
        w.append(hexToData(v.groth16.super_root_hex))
        w.append(wsolAsset)
        w.append(Data(repeating: 0, count: 32))
        w.append(u64Le(0))
        w.append(u64Le(0))
        w.append(ctxPriv)
        w.append(1) // omit_nf1 = true

        // Input 0: real note at lane 2, leaf 5
        w.append(alice.spendSk)
        w.append(enc.tweak)
        w.append(wsolAsset)
        w.append(u64Le(v.memo.amount))
        w.append(enc.blinding)
        w.append(0) // is_dummy = false
        var pos = [UInt8](repeating: 0, count: 20)
        pos[0] = 1
        pos[1] = 1
        pos[18] = 2
        w.append(contentsOf: pos)
        for zh in zeroHashes {
            let z = hexToData(zh)
            w.append(z)
            w.append(z)
            w.append(z)
        }

        // Input 1: dummy
        w.append(alice.spendSk)
        w.append(Data(repeating: 0, count: 32))
        w.append(wsolAsset)
        w.append(u64Le(0))
        w.append(u64Be32(0x5555))
        w.append(1) // is_dummy = true
        w.append(Data(repeating: 0, count: 20 + 20 * 3 * 32))

        // Outputs 0, 1, 2
        w.append(hexToData(v.groth16.out0_stealth_owner_hex))
        w.append(wsolAsset)
        w.append(u64Le(1_000_000))
        w.append(u64Be32(0x201))

        w.append(hexToData(v.groth16.out1_stealth_owner_hex))
        w.append(wsolAsset)
        w.append(u64Le(500_000))
        w.append(u64Be32(0x202))

        w.append(Data(repeating: 0, count: 32))
        w.append(wsolAsset)
        w.append(u64Le(0))
        w.append(u64Be32(0x203))
        XCTAssertEqual(w.count, 4611)

        let proved = try proveJoinsplitWitnessBytes(witness4611: w, seed32: Data(repeating: 0x99, count: 32))
        XCTAssertEqual(dataToHex(proved.nf0), v.groth16.nf0_hex)
        XCTAssertEqual(dataToHex(proved.nf1), v.groth16.nf1_hex)
        XCTAssertEqual(dataToHex(proved.cm0), v.groth16.cm0_hex)
        XCTAssertEqual(dataToHex(proved.cm1), v.groth16.cm1_hex)
        XCTAssertEqual(dataToHex(proved.cm2), v.groth16.cm2_hex)
        XCTAssertEqual(dataToHex(proved.publicInputHash), v.groth16.public_input_hash_hex)
        XCTAssertEqual(dataToHex(proved.proof192), v.groth16.proof_192_hex)
    }
}
