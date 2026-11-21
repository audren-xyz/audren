import Foundation
import XCTest
@testable import AudrenSDK

// MARK: - Canonical Test Vector Codable Schema (`spec/test-vectors.json`)

private struct KeyVector: Decodable {
    let seed_hex: String
    let spend_sk_hex: String
    let spend_pk_hex: String
    let view_sk_hex: String
    let view_pk_hex: String
    let address: String
    let full_viewing_key_json: String
}

private struct FvkJson: Decodable {
    let version: UInt8
    let spend_pk_b58: String
    let view_sk_b58: String
    let view_pk_b58: String
}

private struct SubaccountVector: Decodable {
    let account_index: UInt32
    let spend_sk_hex: String
    let spend_pk_hex: String
    let view_sk_hex: String
    let view_pk_hex: String
    let address: String
}

private struct DefiSessionVector: Decodable {
    let session_index: UInt32
    let secret_seed_hex: String
    let pubkey_hex: String
    let address: String
}

private struct PdaVector: Decodable {
    let address: String
    let bump: UInt8
}

private struct PdaSuiteVector: Decodable {
    let pool_id: UInt32
    let pool: PdaVector
    let epoch_page_0: PdaVector
    let epoch_page_lane1_seq0: PdaVector
    let sol_vault: PdaVector
    let vault_auth: PdaVector
    let page_rent_vault: PdaVector
    let escrow_0: PdaVector
    let unwrap_pda: PdaVector
    let lane_1: PdaVector
    let lane_rent_vault_1: PdaVector
    let proof_buffer_authority: String
    let proof_buffer_nonce: UInt64
    let proof_buffer: PdaVector
    let nullifier_pda: PdaVector
}

private struct AssetGeneratorsVector: Decodable {
    let native_sol_mint_b58: String
    let native_sol_gen_hex: String
    let wsol_mint_b58: String
    let wsol_gen_hex: String
    let usdc_mint_b58: String
    let usdc_gen_hex: String
}

private struct PoolStateVector: Decodable {
    let raw_hex: String
    let version: UInt8
    let bump: UInt8
    let mode: UInt8
    let paused: Bool
    let pool_id: UInt32
    let current_page_id: UInt64
    let total_notes: UInt64
    let total_spends: UInt64
    let page_rent_fee_lamports: UInt64
    let authority: String
    let active_lanes: UInt8
}

private struct OwnedNoteVector: Decodable {
    let page_id: UInt64
    let slot_index: UInt8
    let mint_hex: String
    let amount: UInt64
    let is_dynamic_output: Bool
    let stealth_pk_hex: String
    let asset_tag_hex: String
    let commitment_hex: String
    let asset_blinding_hex: String
    let value_blinding_hex: String
    let stealth_scalar_hex: String
    let spend_x_hex: String
    let nullifier_hex: String
    let nullifier_pda: String
}

private struct EpochPageVector: Decodable {
    let pool_id: UInt32
    let page_id: UInt64
    let version: UInt8
    let bump: UInt8
    let closed: Bool
    let count: UInt8
    let created_slot: UInt64
    let closed_slot: UInt64
    let scan_offset: UInt32
    let scan_length: UInt32
    let page_hex: String
    let scan_slice_hex: String
    let matched_slots: [UInt8]
    let alice_note: OwnedNoteVector
}

private struct AuditorVector: Decodable {
    let auditor_seed_hex: String
    let auditor_sk_hex: String
    let auditor_pk_hex: String
    let elgamal_s1_hex: String
    let elgamal_s2_hex: String
    let expected_spent_pk_hex: String
    let elgamal_m1_hex: String
    let elgamal_m2_hex: String
    let expected_asset_gen_hex: String
}

private struct ConformanceVectors: Decodable {
    let spec_version: String
    let program_id: String
    let alice: KeyVector
    let alice_subaccounts: [SubaccountVector]
    let alice_defi_sessions: [DefiSessionVector]
    let bob: KeyVector
    let pdas: PdaSuiteVector
    let asset_generators: AssetGeneratorsVector
    let pool_state: PoolStateVector
    let epoch_page: EpochPageVector
    let selective_disclosure_json: String
    let auditor: AuditorVector
    let jupiter_cpi_excluded_dexes: String
}

// MARK: - Helpers

private func hexToData(_ hex: String) -> Data {
    var data = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        let byte = UInt8(hex[idx..<next], radix: 16)!
        data.append(byte)
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
        .deletingLastPathComponent() // AudrenSDKTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // swift
        .deletingLastPathComponent() // packages
        .deletingLastPathComponent() // repo root
    let url = repoRoot.appendingPathComponent("spec/test-vectors.json")
    let raw = try Data(contentsOf: url)
    return try JSONDecoder().decode(ConformanceVectors.self, from: raw)
}

// MARK: - Conformance Suite (All 6 Building Blocks)

final class ConformanceTests: XCTestCase {
    func testAllSixBuildingBlocksMatchCanonicalVectors() throws {
        let v = try loadVectors()

        // 1. Keys, Sub-Accounts, Addresses, FVK & Asset Generators
        XCTAssertEqual(programId(), v.program_id)

        let aliceSeed = hexToData(v.alice.seed_hex)
        let alice = try deriveKeysFromSeed(seed32: aliceSeed)
        XCTAssertEqual(dataToHex(alice.spendSk), v.alice.spend_sk_hex)
        XCTAssertEqual(dataToHex(alice.spendPk), v.alice.spend_pk_hex)
        XCTAssertEqual(dataToHex(alice.viewSk), v.alice.view_sk_hex)
        XCTAssertEqual(dataToHex(alice.viewPk), v.alice.view_pk_hex)
        XCTAssertEqual(alice.address, v.alice.address)

        let parsed = try parseAudrenAddress(encoded: alice.address)
        XCTAssertEqual(parsed.spendPk, alice.spendPk)
        XCTAssertEqual(parsed.viewPk, alice.viewPk)
        XCTAssertEqual(
            try formatAudrenAddress(spendPk32: parsed.spendPk, viewPk32: parsed.viewPk),
            alice.address
        )

        let fvk = try exportFullViewingKey(seed32: aliceSeed, accountIndex: 0)
        let expectedFvk = try JSONDecoder().decode(
            FvkJson.self,
            from: Data(v.alice.full_viewing_key_json.utf8)
        )
        XCTAssertEqual(fvk.version, expectedFvk.version)
        XCTAssertEqual(fvk.spendPkB58, expectedFvk.spend_pk_b58)
        XCTAssertEqual(fvk.viewSkB58, expectedFvk.view_sk_b58)
        XCTAssertEqual(fvk.viewPkB58, expectedFvk.view_pk_b58)

        for sub in v.alice_subaccounts {
            let derived = try deriveSubaccountKeys(
                masterSeed32: aliceSeed,
                accountIndex: sub.account_index
            )
            XCTAssertEqual(dataToHex(derived.spendSk), sub.spend_sk_hex)
            XCTAssertEqual(dataToHex(derived.spendPk), sub.spend_pk_hex)
            XCTAssertEqual(derived.address, sub.address)
        }

        for sess in v.alice_defi_sessions {
            let derived = try deriveDefiSessionKeypair(
                masterSeed32: aliceSeed,
                sessionIndex: sess.session_index
            )
            XCTAssertEqual(dataToHex(derived.secretSeed), sess.secret_seed_hex)
            XCTAssertEqual(dataToHex(derived.pubkey), sess.pubkey_hex)
            XCTAssertEqual(derived.address, sess.address)
        }

        let nativeSolGen = try assetGenerator(mint32: Data(repeating: 0, count: 32))
        XCTAssertEqual(dataToHex(nativeSolGen), v.asset_generators.native_sol_gen_hex)

        // 2. Canonical PDAs & Account Decoders
        let pid = programId()
        XCTAssertEqual(try derivePoolPda(poolId: 0, programId: pid).address, v.pdas.pool.address)
        XCTAssertEqual(try derivePoolPda(poolId: 0, programId: pid).bump, v.pdas.pool.bump)
        XCTAssertEqual(
            try deriveEpochPagePda(poolId: 0, pageId: 0, programId: pid).address,
            v.pdas.epoch_page_0.address
        )
        XCTAssertEqual(
            try deriveEpochPagePda(poolId: 0, pageId: 1 << 56, programId: pid).address,
            v.pdas.epoch_page_lane1_seq0.address
        )
        XCTAssertEqual(try deriveSolVaultPda(poolId: 0, programId: pid).address, v.pdas.sol_vault.address)
        XCTAssertEqual(try deriveVaultAuthPda(poolId: 0, programId: pid).address, v.pdas.vault_auth.address)
        XCTAssertEqual(try derivePageRentVaultPda(poolId: 0, programId: pid).address, v.pdas.page_rent_vault.address)
        XCTAssertEqual(try deriveEscrowPda(poolId: 0, shardId: 0, programId: pid).address, v.pdas.escrow_0.address)
        XCTAssertEqual(
            try deriveUnwrapPda(poolId: 0, nullifier32: hexToData(v.epoch_page.alice_note.nullifier_hex), programId: pid).address,
            v.pdas.unwrap_pda.address
        )
        XCTAssertEqual(try deriveLanePda(poolId: 0, laneId: 1, programId: pid).address, v.pdas.lane_1.address)
        XCTAssertEqual(try deriveLaneRentVaultPda(poolId: 0, laneId: 1, programId: pid).address, v.pdas.lane_rent_vault_1.address)
        XCTAssertEqual(
            try deriveProofBufferPda(
                authorityB58: v.pdas.proof_buffer_authority,
                nonce: v.pdas.proof_buffer_nonce,
                programId: pid
            ).address,
            v.pdas.proof_buffer.address
        )

        let ps = try decodePoolState(data: hexToData(v.pool_state.raw_hex))
        XCTAssertEqual(ps.version, v.pool_state.version)
        XCTAssertEqual(ps.bump, v.pool_state.bump)
        XCTAssertEqual(ps.mode, v.pool_state.mode)
        XCTAssertEqual(ps.paused, v.pool_state.paused)
        XCTAssertEqual(ps.totalNotes, v.pool_state.total_notes)
        XCTAssertEqual(ps.totalSpends, v.pool_state.total_spends)
        XCTAssertEqual(ps.activeLanes, v.pool_state.active_lanes)

        // 3. Scanner & Note Decryption
        let sliceCfg = pageScanDataSlice()
        XCTAssertEqual(sliceCfg.offset, v.epoch_page.scan_offset)
        XCTAssertEqual(sliceCfg.length, v.epoch_page.scan_length)

        let pageBytes = hexToData(v.epoch_page.page_hex)
        let hdr = try decodeEpochPageHeader(data: pageBytes)
        XCTAssertEqual(hdr.count, v.epoch_page.count)
        XCTAssertEqual(hdr.closed, v.epoch_page.closed)
        XCTAssertEqual(hdr.createdSlot, v.epoch_page.created_slot)
        XCTAssertEqual(hdr.closedSlot, v.epoch_page.closed_slot)

        let hits = try scanPageDataslice(
            pageId: 0,
            slice1056: hexToData(v.epoch_page.scan_slice_hex),
            spendPk32: alice.spendPk,
            viewSk32: alice.viewSk
        )
        XCTAssertEqual(Array(hits), v.epoch_page.matched_slots)

        let notes = try scanEpochPage(
            poolId: 0,
            pageBytes: pageBytes,
            spendSk32: alice.spendSk,
            spendPk32: alice.spendPk,
            viewSk32: alice.viewSk,
            programId: pid
        )
        XCTAssertEqual(notes.count, 1)
        let note = notes[0]
        XCTAssertEqual(note.slotIndex, v.epoch_page.alice_note.slot_index)
        XCTAssertEqual(note.amount, v.epoch_page.alice_note.amount)
        XCTAssertEqual(dataToHex(note.stealthPk), v.epoch_page.alice_note.stealth_pk_hex)
        XCTAssertEqual(dataToHex(note.assetTag), v.epoch_page.alice_note.asset_tag_hex)
        XCTAssertEqual(dataToHex(note.commitment), v.epoch_page.alice_note.commitment_hex)
        XCTAssertEqual(dataToHex(note.nullifier!), v.epoch_page.alice_note.nullifier_hex)
        XCTAssertEqual(note.nullifierPda, v.epoch_page.alice_note.nullifier_pda)

        // Read-only FVK scan (spendSk32 = nil) + corrupted decoy slot isolation
        var poisonedPage = pageBytes
        poisonedPage.replaceSubrange(96..<128, with: Data(repeating: 0xff, count: 32))
        let fvkNotes = try scanEpochPage(
            poolId: 0,
            pageBytes: poisonedPage,
            spendSk32: nil,
            spendPk32: alice.spendPk,
            viewSk32: alice.viewSk,
            programId: pid
        )
        XCTAssertEqual(fvkNotes.count, 1)
        XCTAssertEqual(fvkNotes[0].slotIndex, 5)
        XCTAssertEqual(fvkNotes[0].amount, note.amount)
        XCTAssertNil(fvkNotes[0].nullifier)

        // Lane helpers & Token-2022 transfer fee ceiling math
        let lane1Seq7 = try pageIdForLane(laneId: 1, seq: 7)
        XCTAssertEqual(lane1Seq7, (1 << 56) | 7)
        XCTAssertEqual(laneOfPageId(pageId: lane1Seq7), 1)
        XCTAssertEqual(seqOfPageId(pageId: lane1Seq7), 7)
        XCTAssertEqual(netDepositAmount(grossAmount: 1_000_000, feeBps: 250, maxFee: 10_000), 990_000)
        XCTAssertEqual(netDepositAmount(grossAmount: 1_000_000, feeBps: 250, maxFee: 0), 1_000_000)

        // 4. Local ZK Proof Generation (exact wire lengths + account counts)
        let payer = v.pdas.proof_buffer_authority
        let depIx = try buildDepositInstruction(params: FfiDepositParams(
            programId: pid,
            depositor: payer,
            poolId: 0,
            activePageId: 1,
            recipientAddress: v.bob.address,
            mint32: Data(repeating: 0, count: 32),
            grossAmount: 500_000,
            netAmount: 500_000,
            feeFromAmount: false,
            tokenProgram: nil,
            depositorAta: nil,
            vaultAta: nil
        ))
        XCTAssertEqual(depIx.data.first, 2)
        XCTAssertEqual(depIx.data.count, 139)
        XCTAssertEqual(depIx.accounts.count, 6)

        let xferIx = try buildTransferInstruction(params: FfiTransferParams(
            programId: pid,
            payer: payer,
            poolId: 0,
            outPageId: 1,
            inputPageIds: [0],
            inputPagesBytes: [pageBytes],
            inputNote: note,
            secretIndex: UInt32(note.slotIndex),
            recipientAddress: v.bob.address,
            changeAddress: alice.address,
            payAmount: 900_000,
            auditorPk32: nil
        ))
        XCTAssertEqual(xferIx.data.first, 3)
        XCTAssertEqual(xferIx.data.count, 2_373)
        XCTAssertEqual(xferIx.accounts.count, 8)

        // Merge two distinct Bob SOL notes + assert self-merge rejection!
        let bob = try deriveKeysFromSeed(seed32: hexToData(v.bob.seed_hex))
        let bobSol = try scanEpochPage(
            poolId: 0,
            pageBytes: pageBytes,
            spendSk32: bob.spendSk,
            spendPk32: bob.spendPk,
            viewSk32: bob.viewSk,
            programId: pid
        ).filter { $0.mint == Data(repeating: 0, count: 32) }
        XCTAssertGreaterThanOrEqual(bobSol.count, 2)
        XCTAssertThrowsError(try buildMergeInstruction(params: FfiMergeParams(
            programId: pid,
            payer: payer,
            poolId: 0,
            outPageId: 1,
            input1PageIds: [0],
            input1PagesBytes: [pageBytes],
            note1: note,
            secretIndex1: UInt32(note.slotIndex),
            input2PageIds: [0],
            input2PagesBytes: [pageBytes],
            note2: note,
            secretIndex2: UInt32(note.slotIndex),
            ownerAddress: alice.address,
            auditorPk32: nil
        )))
        let mergeIx = try buildMergeInstruction(params: FfiMergeParams(
            programId: pid,
            payer: payer,
            poolId: 0,
            outPageId: 1,
            input1PageIds: [0],
            input1PagesBytes: [pageBytes],
            note1: bobSol[0],
            secretIndex1: UInt32(bobSol[0].slotIndex),
            input2PageIds: [0],
            input2PagesBytes: [pageBytes],
            note2: bobSol[1],
            secretIndex2: UInt32(bobSol[1].slotIndex),
            ownerAddress: bob.address,
            auditorPk32: nil
        ))
        XCTAssertEqual(mergeIx.data.first, 4)
        XCTAssertEqual(mergeIx.data.count, 2_950)
        XCTAssertEqual(mergeIx.accounts.count, 10)

        let plan = try buildBufferedExecutionPlan(nonce: 42, inner: xferIx)
        XCTAssertEqual(plan.uploadChunks.count, 4)
        XCTAssertEqual(plan.executeIx.data, Data([9, 3]))
        XCTAssertEqual(plan.proofBufferPda, v.pdas.proof_buffer.address)

        let closeIx = try buildCloseProofBufferInstruction(programId: pid, payer: payer, nonce: 42)
        XCTAssertEqual(closeIx.data, Data([10]))
        XCTAssertEqual(closeIx.accounts.count, 2)
        XCTAssertEqual(closeIx.accounts[1].pubkey, plan.proofBufferPda)

        let openIx = try buildOpenPageInstruction(programId: pid, payer: payer, poolId: 0, currentPageId: 0)
        XCTAssertEqual(openIx.data, Data([1]))
        XCTAssertEqual(openIx.accounts.count, 6)

        let openLaneIx = try buildOpenLanePageInstruction(programId: pid, payer: payer, poolId: 0, currentPageId: 1 << 56)
        XCTAssertEqual(openLaneIx.data, Data([12, 1]))
        XCTAssertEqual(openLaneIx.accounts.count, 7)
        XCTAssertFalse(openLaneIx.accounts[1].isWritable)

        let wdIx = try buildWithdrawInstruction(params: FfiWithdrawParams(
            programId: pid,
            payer: payer,
            poolId: 0,
            outPageId: 1,
            inputPageIds: [0],
            inputPagesBytes: [pageBytes],
            inputNote: note,
            secretIndex: UInt32(note.slotIndex),
            recipientAccount: payer,
            changeAddress: alice.address,
            amount: 1_000_000,
            relayerFee: 0,
            feeRecipient: nil,
            unwrapWsol: false,
            splTokenProgram: nil,
            auditorPk32: nil
        ))
        XCTAssertEqual(wdIx.data.first, 6)
        XCTAssertEqual(wdIx.data.count, 1_973)
        XCTAssertEqual(wdIx.accounts.count, 11)

        let wdFullIx = try buildWithdrawInstruction(params: FfiWithdrawParams(
            programId: pid,
            payer: payer,
            poolId: 0,
            outPageId: 1,
            inputPageIds: [0],
            inputPagesBytes: [pageBytes],
            inputNote: note,
            secretIndex: UInt32(note.slotIndex),
            recipientAccount: payer,
            changeAddress: alice.address,
            amount: note.amount,
            relayerFee: 0,
            feeRecipient: nil,
            unwrapWsol: false,
            splTokenProgram: nil,
            auditorPk32: nil
        ))
        XCTAssertEqual(wdFullIx.data.first, 6)
        XCTAssertEqual(wdFullIx.data.count, 948)
        XCTAssertFalse(wdFullIx.accounts[1].isWritable)

        // 5. Selective Disclosure & Institutional Auditor Decrypt
        let sd = createSelectiveDisclosureProof(note: note)
        XCTAssertTrue(try verifySelectiveDisclosureProof(proof: sd))
        XCTAssertTrue(try verifySelectiveDisclosureOnPage(proof: sd, pageBytes: pageBytes))

        let tampered = FfiSelectiveDisclosureProof(
            version: sd.version,
            pageId: sd.pageId,
            slotIndex: sd.slotIndex,
            stealthPkB58: sd.stealthPkB58,
            assetTagB58: sd.assetTagB58,
            commitmentB58: sd.commitmentB58,
            mintB58: sd.mintB58,
            amount: sd.amount + 1,
            assetBlindingB58: sd.assetBlindingB58,
            valueBlindingB58: sd.valueBlindingB58
        )
        XCTAssertFalse(try verifySelectiveDisclosureProof(proof: tampered))
        XCTAssertFalse(try verifySelectiveDisclosureOnPage(proof: tampered, pageBytes: pageBytes))

        let aud = try deriveAuditorKeypair(seed32: hexToData(v.auditor.auditor_seed_hex))
        XCTAssertEqual(dataToHex(aud.auditorPk), v.auditor.auditor_pk_hex)
        let dec = try auditorDecryptNote(
            auditorSk32: aud.auditorSk,
            s132: hexToData(v.auditor.elgamal_s1_hex),
            s232: hexToData(v.auditor.elgamal_s2_hex),
            m132: hexToData(v.auditor.elgamal_m1_hex),
            m232: hexToData(v.auditor.elgamal_m2_hex)
        )
        XCTAssertEqual(dataToHex(dec.spentStealthPk), v.auditor.expected_spent_pk_hex)
        XCTAssertEqual(dataToHex(dec.assetGenerator), v.auditor.expected_asset_gen_hex)

        // 6. Escrow & Relayer (including prepareEscrowAccounts + ATA derivation + signer stripping)
        XCTAssertEqual(jupiterCpiExcludedDexes().joined(separator: ","), v.jupiter_cpi_excluded_dexes)
        XCTAssertEqual(defaultRelayUrl(), "https://relay.audren.xyz")

        let classicTp = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        let escrow0 = v.pdas.escrow_0.address
        let escrowInAta = try deriveAssociatedTokenAddress(
            ownerB58: escrow0,
            mintB58: v.asset_generators.wsol_mint_b58,
            tokenProgramB58: classicTp
        )
        let escrowOutAta = try deriveAssociatedTokenAddress(
            ownerB58: escrow0,
            mintB58: v.asset_generators.usdc_mint_b58,
            tokenProgramB58: classicTp
        )
        let prep = try prepareEscrowAccounts(
            poolId: 0,
            shardId: 0,
            inputMintB58: v.asset_generators.wsol_mint_b58,
            outputMintB58: v.asset_generators.usdc_mint_b58,
            inputTokenProgramB58: classicTp,
            outputTokenProgramB58: classicTp,
            actionAccounts: [
                FfiAccountMeta(pubkey: escrowInAta, isSigner: false, isWritable: true),
                FfiAccountMeta(pubkey: escrow0, isSigner: true, isWritable: true),
                FfiAccountMeta(pubkey: escrowOutAta, isSigner: false, isWritable: true),
            ],
            programId: pid
        )
        XCTAssertEqual(prep.escrowPda, escrow0)
        XCTAssertEqual(prep.escrowInAta, escrowInAta)
        XCTAssertEqual(prep.escrowOutAta, escrowOutAta)
        XCTAssertEqual(prep.escrowIdx, 1)
        XCTAssertEqual(prep.escrowInIdx, 0)
        XCTAssertEqual(prep.escrowOutIdx, 2)
        XCTAssertFalse(prep.accounts[1].isSigner)
    }
}
