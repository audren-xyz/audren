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
    let sol_vault: PdaEntry
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
    let native_sol_asset_id_hex: String
    let wsol_asset_id_hex: String
    let usdc_mint_b58: String
    let usdc_asset_id_hex: String
}

private struct MemoVector: Decodable {
    let eph_secret_hex: String
    let amount: UInt64
    let mint_hex: String
    let tweak_hex: String
    let blinding_hex: String
    let stealth_owner_hex: String
    let commitment_hex: String
    let memo_90_hex: String
    let dyn_head_34_hex: String
    let dyn_mask_56_hex: String
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
    let joinsplit_private_ctx_hash_hex: String
    let joinsplit_wsol_unwrap_ctx_hash_hex: String
    let exec_fee_on_output_ctx_hash_hex: String
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
    let selective_disclosure: SelectiveDisclosureVector
    let ctx_hashes: CtxHashVectors
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
    func testV2ConformanceVectors() throws {
        let v = try loadVectors()

        XCTAssertEqual(protocolVersion(), v.protocol_version)
        XCTAssertEqual(canonicalProgramId(), v.program_id)

        // 1. Keys, Subaccounts, FVK, aud1 Address, DeFi Sessions
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

        // 2. Asset ID & 13 V2 PDAs
        XCTAssertEqual(
            dataToHex(try deriveAssetIdBytes(mintBytes: Data(repeating: 0, count: 32))),
            v.asset_ids.native_sol_asset_id_hex
        )
        let pid = v.program_id
        let nf = hexToData(v.pdas.nullifier_hex)
        XCTAssertEqual(try derivePoolPda(programId: pid, poolId: v.pdas.pool_id).address, v.pdas.pool.address)
        XCTAssertEqual(try deriveSolVaultPda(programId: pid, poolId: v.pdas.pool_id).address, v.pdas.sol_vault.address)
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

        // 3. Memo Crypto + FVK Commitment Verify + Mode 1 Selective Disclosure
        let enc = try encryptNoteMemo(
            recipientSpendPk: alice.spendPk,
            recipientViewPk: alice.viewPk,
            ephSecret: hexToData(v.memo.eph_secret_hex),
            amount: v.memo.amount,
            mint: hexToData(v.memo.mint_hex)
        )
        XCTAssertEqual(dataToHex(enc.memo90), v.memo.memo_90_hex)
        XCTAssertEqual(dataToHex(enc.commitment), v.memo.commitment_hex)

        let dec = try decryptAndVerifyMemoEntry(fvk: fvk, memo90: enc.memo90, onchainCommitment: enc.commitment)
        XCTAssertNotNil(dec)
        XCTAssertEqual(dec?.amount, v.memo.amount)

        let dynM = try prepareDynamicSwapMemo(recipientViewPk: hexToData(v.bob.view_pk_hex), ephSecret: Data(repeating: 0x44, count: 32))
        XCTAssertEqual(dataToHex(dynM.dynHead34), v.memo.dyn_head_34_hex)
        XCTAssertEqual(dataToHex(dynM.dynMask56), v.memo.dyn_mask_56_hex)

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
        let ctxPriv = try computeJoinsplitCtxHashFfi(params: FfiJoinSplitCtxHashParams(
            programId: pid,
            poolId: 0,
            outLaneId: 2,
            outputMask: 0b111,
            assetMode: 0,
            unwrapWsol: false,
            recipient: nil,
            relayerFeeRecipient: nil,
            publicAssetId: Data(repeating: 0, count: 32),
            publicAmountOut: 0,
            relayerFeeAmount: 0,
            memosBytes: enc.memo90
        ))
        XCTAssertEqual(dataToHex(ctxPriv), v.ctx_hashes.joinsplit_private_ctx_hash_hex)

        let ps = try decodePoolStateAccount(data: hexToData(v.pool_state.raw_hex))
        XCTAssertEqual(ps.activeLanes, v.pool_state.active_lanes)
        XCTAssertEqual(ps.ckptInterval, v.pool_state.ckpt_interval)

        let ck = try decodeRootCheckpointAccount(data: hexToData(v.checkpoint_raw_hex))
        XCTAssertEqual(ck.slotIdx, 13)
        XCTAssertEqual(ck.laneCounts[2], 6)
        XCTAssertEqual(defaultRelayUrl(), "https://relay.audren.xyz")
        XCTAssertFalse(jupiterCpiExcludedDexes().isEmpty)
    }
}
