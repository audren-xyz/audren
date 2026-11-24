package xyz.audren.sdk

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConformanceTest {
    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun jsonByteArray(arr: JSONArray): ByteArray =
        ByteArray(arr.length()) { i -> arr.getInt(i).toByte() }

    @Test
    fun conformanceVectorsMatchSpec() {
        val specFile = File("../../spec/test-vectors.json").canonicalFile
        val v = JSONObject(specFile.readText())

        assertEquals(v.getInt("protocol_version").toUByte(), protocolVersion())
        val pid = v.getString("program_id")
        assertEquals(pid, canonicalProgramId())

        // 1. Keys, Subaccounts, FVK, BIP-350 Bech32m aud1 address, DeFi sessions
        val aliceVec = v.getJSONObject("alice")
        val aliceSeed = hexToBytes(aliceVec.getString("seed_hex"))
        val alice = deriveKeysFromSeed(aliceSeed)
        assertEquals(aliceVec.getString("spend_sk_hex"), bytesToHex(alice.spendSk))
        assertEquals(aliceVec.getString("spend_pk_hex"), bytesToHex(alice.spendPk))
        assertEquals(aliceVec.getString("nk_hex"), bytesToHex(alice.nk))
        assertEquals(aliceVec.getString("view_sk_hex"), bytesToHex(alice.viewSk))
        assertEquals(aliceVec.getString("view_pk_hex"), bytesToHex(alice.viewPk))
        assertEquals(aliceVec.getString("address"), alice.address)

        val decoded = decodeAudrenAddress(alice.address)
        assertEquals(aliceVec.getString("spend_pk_hex"), bytesToHex(decoded[0]))
        assertEquals(aliceVec.getString("view_pk_hex"), bytesToHex(decoded[1]))

        val sub1 = deriveSubaccountKeys(aliceSeed, 1u)
        assertEquals(v.getJSONObject("alice_sub1").getString("address"), sub1.address)

        val fvk = exportFullViewingKey(aliceSeed)
        assertEquals(aliceVec.getString("nk_hex"), bytesToHex(fvk.nk))

        val s0 = deriveDefiSessionKeypair(aliceSeed, 0u)
        assertEquals(v.getJSONObject("defi_session_0").getString("pubkey_b58"), s0.pubkeyB58)
        val s3 = deriveDefiSessionKeypair(aliceSeed, 3u)
        assertEquals(v.getJSONObject("defi_session_3").getString("pubkey_b58"), s3.pubkeyB58)

        // 2. Asset ID & 12 Canonical v1 PDAs
        val memoVec = v.getJSONObject("memo")
        val wsolMint = hexToBytes(memoVec.getString("mint_hex"))
        assertEquals(
            v.getJSONObject("asset_ids").getString("wsol_asset_id_hex"),
            bytesToHex(deriveAssetIdBytes(wsolMint))
        )
        val p = v.getJSONObject("pdas")
        val poolId = p.getLong("pool_id").toUInt()
        val laneId = p.getInt("lane_id").toUByte()
        val pageSeq = p.getLong("page_seq").toULong()
        val shardId = p.getInt("shard_id").toUByte()
        val nf = hexToBytes(p.getString("nullifier_hex"))

        assertEquals(p.getJSONObject("pool").getString("address"), derivePoolPda(pid, poolId).address)
        assertEquals(p.getJSONObject("vault_auth").getString("address"), deriveVaultAuthPda(pid, poolId).address)
        assertEquals(p.getJSONObject("lane").getString("address"), deriveLanePda(pid, poolId, laneId).address)
        assertEquals(p.getJSONObject("lane_rent").getString("address"), deriveLaneRentPda(pid, poolId, laneId).address)
        assertEquals(p.getJSONObject("subtree").getString("address"), deriveSubtreePda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("subroot").getString("address"), deriveSubrootPda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("memo").getString("address"), deriveMemoPda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("nf_page").getString("address"), deriveNfPagePda(pid, poolId, laneId, pageSeq).address)
        val rootsPda = deriveRootsPda(pid, poolId)
        assertEquals(p.getJSONObject("roots").getString("address"), rootsPda.address)
        assertEquals(p.getJSONObject("roots").getInt("bump").toUByte(), rootsPda.bump)
        assertEquals(p.getJSONObject("nullifier").getString("address"), deriveNullifierPda(pid, poolId, nf).address)
        assertEquals(p.getJSONObject("escrow").getString("address"), deriveEscrowPda(pid, poolId, shardId).address)
        assertEquals(p.getJSONObject("unwrap").getString("address"), deriveUnwrapPda(pid, poolId, nf).address)

        // 3. Versioned 106 B Memo Crypto + FVK Verify + Low-Order X25519 + Selective Disclosure
        val paymentId = hexToBytes(memoVec.getString("payment_id_hex"))
        val enc = encryptNoteMemo(
            alice.spendPk,
            alice.viewPk,
            hexToBytes(memoVec.getString("eph_secret_hex")),
            memoVec.getLong("amount").toULong(),
            wsolMint,
            paymentId
        )
        assertEquals(memoVec.getString("memo_106_hex"), bytesToHex(enc.memo106))
        assertEquals(memoVec.getString("commitment_hex"), bytesToHex(enc.commitment))

        val dec = decryptAndVerifyMemoEntry(fvk, enc.memo106, enc.commitment)
        assertNotNull(dec)
        assertEquals(memoVec.getLong("amount").toULong(), dec.amount)
        assertEquals(memoVec.getString("payment_id_hex"), bytesToHex(dec.paymentId))

        val lowVec = v.getJSONObject("low_order_x25519")
        assertFalse(checkMemoViewTag(fvk, ByteArray(2), hexToBytes(lowVec.getString("all_zero_epk_hex"))))
        assertFalse(checkMemoViewTag(fvk, ByteArray(2), hexToBytes(lowVec.getString("order_8_epk_hex"))))

        val bobVpk = hexToBytes(v.getJSONObject("bob").getString("view_pk_hex"))
        val dynM = prepareDynamicSwapMemo(bobVpk, hexToBytes(memoVec.getString("dyn_eph_secret_hex")))
        assertEquals(memoVec.getString("dyn_head_34_hex"), bytesToHex(dynM.dynHead34))
        assertEquals(memoVec.getString("dyn_mask_72_hex"), bytesToHex(dynM.dynMask72))

        val sdVec = v.getJSONObject("selective_disclosure")
        val sd = FfiSelectiveDisclosureProof(
            poolId = sdVec.getLong("pool_id").toUInt(),
            laneId = sdVec.getInt("lane_id").toUByte(),
            leafIndex = sdVec.getLong("leaf_index").toULong(),
            stealthOwner = jsonByteArray(sdVec.getJSONArray("stealth_owner")),
            mint = jsonByteArray(sdVec.getJSONArray("mint")),
            amount = sdVec.getLong("amount").toULong(),
            blinding = jsonByteArray(sdVec.getJSONArray("blinding")),
            commitment = jsonByteArray(sdVec.getJSONArray("commitment"))
        )
        assertTrue(verifySelectiveDisclosureProof(sd, enc.commitment))

        // 4. Context Hash & Account Decoders
        val ctxPriv = computeTransactCtxHashFfi(
            FfiTransactCtxHashParams(
                programId = pid,
                poolId = 0u,
                vkId = 0u,
                outLaneId = 2u,
                outputMask = 7u,
                assetMode = 0u,
                unwrapWsol = false,
                recipient = null,
                relayerFeeRecipient = null,
                publicAssetId = ByteArray(32),
                publicAmountOut = 0uL,
                relayerFeeAmount = 0uL,
                memosBytes = enc.memo106
            )
        )
        assertEquals(
            v.getJSONObject("ctx_hashes").getString("transact_private_ctx_hash_hex"),
            bytesToHex(ctxPriv)
        )

        val psVec = v.getJSONObject("pool_state")
        val ps = decodePoolStateAccount(hexToBytes(psVec.getString("raw_hex")))
        assertEquals(psVec.getInt("active_lanes").toUByte(), ps.activeLanes)
        assertEquals(psVec.getLong("root_epoch_interval").toULong(), ps.rootEpochInterval)
        assertEquals(psVec.getString("pending_authority_b58"), ps.pendingAuthorityB58)

        val rhVec = v.getJSONObject("root_history")
        val rhRaw = hexToBytes(rhVec.getString("raw_hex"))
        assertEquals(rhVec.getInt("account_len"), rhRaw.size)
        val rh = decodeGlobalRootHistoryAccount(rhRaw)
        assertEquals(rhVec.getLong("pool_id").toUInt(), rh.poolId)
        assertEquals(rhVec.getInt("bump").toUByte(), rh.bump)
        assertEquals(rhVec.getInt("slot_cursor").toUShort(), rh.slotCursor)
        assertEquals(rhVec.getInt("epoch_cursor").toUShort(), rh.epochCursor)
        assertEquals(rhVec.getInt("slot_count").toUShort(), rh.slotCount)
        assertEquals(rhVec.getInt("epoch_count").toUShort(), rh.epochCount)
        assertEquals(rhVec.getLong("latest_slot").toULong(), rh.latestSlot)
        assertEquals(rhVec.getLong("stable_epoch_id").toULong(), rh.stableEpochId)
        assertEquals(rhVec.getLong("stable_slot").toULong(), rh.stableSlot)
        assertEquals(rhVec.getLong("epoch_interval").toULong(), rh.epochInterval)
        assertEquals(rhVec.getString("latest_super_root_hex"), bytesToHex(rh.latestSuperRoot))
        assertEquals(rhVec.getString("stable_super_root_hex"), bytesToHex(rh.stableSuperRoot))
        assertEquals(rhVec.getLong("lane2_leaf_count").toULong(), rh.latestLaneCounts[2])
        assertEquals(rhVec.getLong("lane2_leaf_count").toULong(), rh.stableLaneCounts[2])
        assertEquals("https://relay.audren.xyz", defaultRelayUrl())
        assertTrue(jupiterCpiExcludedDexes().isNotEmpty())

        // 5. Native BN254 Groth16 proving via `proveJoinsplitWitnessBytes`
        val zeroHashes = listOf(
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
            "16e195c570f224cc86219527096fa55516cc9ee1b96764dd263db0884983fdaf"
        )
        fun u64Le(x: Long): ByteArray = ByteArray(8) { i -> ((x ushr (i * 8)) and 0xff).toByte() }
        fun u64Be32(x: Long): ByteArray = ByteArray(32).also { b ->
            for (i in 0 until 8) b[24 + i] = ((x ushr ((7 - i) * 8)) and 0xff).toByte()
        }
        val g16 = v.getJSONObject("groth16")
        val wsolAsset = hexToBytes(v.getJSONObject("asset_ids").getString("wsol_asset_id_hex"))
        val w = java.io.ByteArrayOutputStream(4611)
        w.write(hexToBytes(g16.getString("super_root_hex")))
        w.write(wsolAsset)
        w.write(ByteArray(32))
        w.write(u64Le(0L))
        w.write(u64Le(0L))
        w.write(ctxPriv)
        w.write(1) // omit_nf1 = true

        // Input 0: real note at lane 2, leaf 5
        w.write(alice.spendSk)
        w.write(enc.tweak)
        w.write(wsolAsset)
        w.write(u64Le(memoVec.getLong("amount")))
        w.write(enc.blinding)
        w.write(0) // is_dummy = false
        val pos = ByteArray(20)
        pos[0] = 1
        pos[1] = 1
        pos[18] = 2
        w.write(pos)
        for (zh in zeroHashes) {
            val z = hexToBytes(zh)
            repeat(3) { w.write(z) }
        }

        // Input 1: dummy
        w.write(alice.spendSk)
        w.write(ByteArray(32))
        w.write(wsolAsset)
        w.write(u64Le(0L))
        w.write(u64Be32(0x5555L))
        w.write(1) // is_dummy = true
        w.write(ByteArray(20 + 20 * 3 * 32))

        // Outputs 0, 1, 2
        w.write(hexToBytes(g16.getString("out0_stealth_owner_hex")))
        w.write(wsolAsset)
        w.write(u64Le(1_000_000L))
        w.write(u64Be32(0x201L))

        w.write(hexToBytes(g16.getString("out1_stealth_owner_hex")))
        w.write(wsolAsset)
        w.write(u64Le(500_000L))
        w.write(u64Be32(0x202L))

        w.write(ByteArray(32))
        w.write(wsolAsset)
        w.write(u64Le(0L))
        w.write(u64Be32(0x203L))

        val witnessBytes = w.toByteArray()
        assertEquals(4611, witnessBytes.size)

        val proved = proveJoinsplitWitnessBytes(witnessBytes, ByteArray(32) { 0x99.toByte() })
        assertEquals(g16.getString("nf0_hex"), bytesToHex(proved.nf0))
        assertEquals(g16.getString("nf1_hex"), bytesToHex(proved.nf1))
        assertEquals(g16.getString("cm0_hex"), bytesToHex(proved.cm0))
        assertEquals(g16.getString("cm1_hex"), bytesToHex(proved.cm1))
        assertEquals(g16.getString("cm2_hex"), bytesToHex(proved.cm2))
        assertEquals(g16.getString("public_input_hash_hex"), bytesToHex(proved.publicInputHash))
        assertEquals(g16.getString("proof_192_hex"), bytesToHex(proved.proof192))

        // 6. UniFFI zero-panic & extraWritablePubkeys & strict address/bounds checks
        assertFailsWith<AudrenFfiException> { decodeAudrenAddress(" " + alice.address) }
        assertFailsWith<AudrenFfiException> { buildOpenPageIx(pid, s0.pubkeyB58, 4u, 0u, 0u, 0uL) }
        assertFailsWith<AudrenFfiException> { deriveLanePda(pid, 0u, 16u) }
        assertFailsWith<AudrenFfiException> { buildInitRootHistoryIx(pid, s0.pubkeyB58, 0u, 0uL, 4u) }
        val initRhIx = buildInitRootHistoryIx(pid, s0.pubkeyB58, 0u, 32uL, 4u)
        assertEquals(rhVec.getInt("tag_init_root_history").toByte(), initRhIx.data[0])
        assertEquals(8, initRhIx.accounts.size)
        assertFailsWith<AudrenFfiException> {
            buildTransactIx(
                FfiTransactParams(
                    programId = pid,
                    payer = s0.pubkeyB58,
                    poolId = 0u,
                    vkId = 0u,
                    rootRingKind = 0u,
                    rootRingIdx = 0u,
                    outLaneId = 2u,
                    outSubSeq = 0uL,
                    outRootSeq = 0uL,
                    outMemoSeq = 0uL,
                    outNfSeq = 0uL,
                    nextSubSeq = null,
                    nextMemoSeq = null,
                    nextNfSeq = null,
                    outputMask = 0u,
                    assetMode = 1u,
                    unwrapWsol = false,
                    publicMint = null,
                    publicVaultAta = null,
                    publicTokenProg = null,
                    proof192 = proved.proof192,
                    nf0 = proved.nf0,
                    nf1 = proved.nf1,
                    cm0 = proved.cm0,
                    cm1 = proved.cm1,
                    cm2 = proved.cm2,
                    publicAmountOut = 1uL,
                    relayerFeeAmount = 0uL,
                    recipient = s0.pubkeyB58,
                    relayerFeeRecipient = s0.pubkeyB58,
                    memosBytes = ByteArray(0),
                    transferHookAccounts = emptyList()
                )
            )
        }
        assertFalse(verifySelectiveDisclosureProof(sd.copy(laneId = 16u), enc.commitment))

        val hPromoted = computeExecCtxHashFfi(
            FfiExecCtxHashParams(
                programId = pid,
                poolId = 0u,
                vkId = 0u,
                outLaneId = 1u,
                escrowShard = 3u,
                changeMask = 0u,
                feeOnOutput = false,
                assetIn = ByteArray(32) { 1 },
                amountIn = 100uL,
                relayerFeeAmount = 0uL,
                relayerFeeRecipient = null,
                assetOut = ByteArray(32) { 2 },
                minAmountOut = 50uL,
                routerProg = s0.pubkeyB58,
                routerAccounts = listOf(FfiAccountMeta(s3.pubkeyB58, false, false)),
                extraWritablePubkeys = listOf(s3.pubkeyB58),
                outStealthOwner = ByteArray(32) { 3 },
                outBlinding = ByteArray(32) { 4 },
                dynMemoHead = ByteArray(34) { 5 },
                dynMask72 = ByteArray(72) { 6 },
                routerIxData = byteArrayOf(1, 2),
                changeMemos = ByteArray(0)
            )
        )
        val hExplicit = computeExecCtxHashFfi(
            FfiExecCtxHashParams(
                programId = pid,
                poolId = 0u,
                vkId = 0u,
                outLaneId = 1u,
                escrowShard = 3u,
                changeMask = 0u,
                feeOnOutput = false,
                assetIn = ByteArray(32) { 1 },
                amountIn = 100uL,
                relayerFeeAmount = 0uL,
                relayerFeeRecipient = null,
                assetOut = ByteArray(32) { 2 },
                minAmountOut = 50uL,
                routerProg = s0.pubkeyB58,
                routerAccounts = listOf(FfiAccountMeta(s3.pubkeyB58, false, true)),
                extraWritablePubkeys = emptyList(),
                outStealthOwner = ByteArray(32) { 3 },
                outBlinding = ByteArray(32) { 4 },
                dynMemoHead = ByteArray(34) { 5 },
                dynMask72 = ByteArray(72) { 6 },
                routerIxData = byteArrayOf(1, 2),
                changeMemos = ByteArray(0)
            )
        )
        assertEquals(bytesToHex(hExplicit), bytesToHex(hPromoted))

        // 7. v1.3.0 Auto-OpenPage custom programId, Token-2022 ATA CU limits, and zero-rent parity
        val plannedDefault = planAutoOpenPages(
            programId = pid,
            poolId = 0u,
            laneId = 0u,
            nextLeaf = 86uL,
            nfCount = 540uL,
            numOutputs = 1u,
            numNfs = 1u,
            existingPages = emptyList()
        )
        assertEquals(2, plannedDefault.size)
        assertEquals(2u.toUByte(), plannedDefault[0].pageKind)
        assertEquals(deriveMemoPda(pid, 0u, 0u, 1uL).address, plannedDefault[0].pdaB58)
        assertEquals(3u.toUByte(), plannedDefault[1].pageKind)
        assertEquals(deriveNfPagePda(pid, 0u, 0u, 1uL).address, plannedDefault[1].pdaB58)

        val customPid = s0.pubkeyB58
        val plannedCustom = planAutoOpenPages(
            programId = customPid,
            poolId = 0u,
            laneId = 0u,
            nextLeaf = 86uL,
            nfCount = 540uL,
            numOutputs = 1u,
            numNfs = 1u,
            existingPages = emptyList()
        )
        assertEquals(2, plannedCustom.size)
        assertEquals(deriveMemoPda(customPid, 0u, 0u, 1uL).address, plannedCustom[0].pdaB58)
        assertTrue(plannedCustom[0].pdaB58 != plannedDefault[0].pdaB58)
        val filteredCustom = planAutoOpenPages(
            programId = customPid,
            poolId = 0u,
            laneId = 0u,
            nextLeaf = 86uL,
            nfCount = 540uL,
            numOutputs = 1u,
            numNfs = 1u,
            existingPages = listOf(plannedCustom[0])
        )
        assertEquals(1, filteredCustom.size)
        assertEquals(plannedCustom[1].pdaB58, filteredCustom[0].pdaB58)
        val filteredCustomCoord = planAutoOpenPages(
            programId = customPid,
            poolId = 0u,
            laneId = 0u,
            nextLeaf = 86uL,
            nfCount = 540uL,
            numOutputs = 1u,
            numNfs = 1u,
            existingPages = listOf(FfiOpenPageSpec(pageKind = 2u, pageSeq = 1uL, pdaB58 = ""))
        )
        assertEquals(1, filteredCustomCoord.size)
        assertEquals(plannedCustom[1].pdaB58, filteredCustomCoord[0].pdaB58)
        assertFailsWith<AudrenFfiException> {
            planAutoOpenPages("not-valid-pid!!!", 0u, 0u, 86uL, 0uL, 1u, 0u, emptyList())
        }

        assertEquals(87_500u, recommendedCuLimitOpenPage(2u, byteArrayOf(250.toByte())))
        assertEquals(
            (140_000 + 40_000 + 30_000 + 2 * 45_000 + 7_500).toUInt(),
            recommendedCuLimitDeposit(
                hasTransferHook = true,
                openPageCount = 1u,
                createAtaCount = 1u,
                createToken2022AtaCount = 2u,
                bumps = byteArrayOf(253.toByte(), 252.toByte())
            )
        )
        assertEquals(
            (295_000 + 40_000 + 30_000 + 2 * 45_000 + 1_500).toUInt(),
            recommendedCuLimitTransact(
                isPublicWithdraw = true,
                hasTransferHook = true,
                outputMask = 0b001u,
                openPageCount = 1u,
                createAtaCount = 1u,
                createToken2022AtaCount = 2u,
                bumps = byteArrayOf(254.toByte())
            )
        )
        assertEquals(
            (285_000 + 25_000 + 300_000 + 40_000 + 30_000 + 2 * 45_000 + 22_500).toUInt(),
            recommendedCuLimitExecViaEscrow(
                routerCuLimit = 300_000u,
                hasToken2022Leg = true,
                openPageCount = 1u,
                createAtaCount = 1u,
                createToken2022AtaCount = 2u,
                bumps = byteArrayOf(240.toByte(), 255.toByte())
            )
        )
        assertEquals(
            1_400_000u,
            recommendedCuLimitExecViaEscrow(
                routerCuLimit = 1_300_000u,
                hasToken2022Leg = true,
                openPageCount = 2u,
                createAtaCount = 1u,
                createToken2022AtaCount = 2u,
                bumps = byteArrayOf(0, 0)
            )
        )

        assertEquals(3uL, deterministicNoteRentFeeFfi(10_000_000uL, 0uL, 0uL, 0uL))
        assertEquals(2uL, deterministicNoteRentFeeFfi(2uL, 0uL, 0uL, 0uL))
        assertEquals(0uL, deterministicNoteRentFeeFfi(0uL, 0uL, 0uL, 0uL))
    }
}
