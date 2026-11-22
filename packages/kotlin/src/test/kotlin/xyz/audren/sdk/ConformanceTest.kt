package xyz.audren.sdk

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
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

        // 1. Keys, Subaccounts, FVK, aud1 address, DeFi sessions
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

        // 2. Asset ID & 13 Canonical PDAs
        assertEquals(
            v.getJSONObject("asset_ids").getString("native_sol_asset_id_hex"),
            bytesToHex(deriveAssetIdBytes(ByteArray(32)))
        )
        val p = v.getJSONObject("pdas")
        val poolId = p.getLong("pool_id").toUInt()
        val laneId = p.getInt("lane_id").toUByte()
        val pageSeq = p.getLong("page_seq").toULong()
        val slotIdx = p.getInt("slot_idx").toUShort()
        val shardId = p.getInt("shard_id").toUByte()
        val nf = hexToBytes(p.getString("nullifier_hex"))

        assertEquals(p.getJSONObject("pool").getString("address"), derivePoolPda(pid, poolId).address)
        assertEquals(p.getJSONObject("sol_vault").getString("address"), deriveSolVaultPda(pid, poolId).address)
        assertEquals(p.getJSONObject("vault_auth").getString("address"), deriveVaultAuthPda(pid, poolId).address)
        assertEquals(p.getJSONObject("lane").getString("address"), deriveLanePda(pid, poolId, laneId).address)
        assertEquals(p.getJSONObject("lane_rent").getString("address"), deriveLaneRentPda(pid, poolId, laneId).address)
        assertEquals(p.getJSONObject("subtree").getString("address"), deriveSubtreePda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("subroot").getString("address"), deriveSubrootPda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("memo").getString("address"), deriveMemoPda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("nf_page").getString("address"), deriveNfPagePda(pid, poolId, laneId, pageSeq).address)
        assertEquals(p.getJSONObject("checkpoint").getString("address"), deriveCheckpointPda(pid, poolId, slotIdx).address)
        assertEquals(p.getJSONObject("nullifier").getString("address"), deriveNullifierPda(pid, poolId, nf).address)
        assertEquals(p.getJSONObject("escrow").getString("address"), deriveEscrowPda(pid, poolId, shardId).address)
        assertEquals(p.getJSONObject("unwrap").getString("address"), deriveUnwrapPda(pid, poolId, nf).address)

        // 3. Memo Crypto + FVK Verify + Selective Disclosure
        val memoVec = v.getJSONObject("memo")
        val enc = encryptNoteMemo(
            alice.spendPk,
            alice.viewPk,
            hexToBytes(memoVec.getString("eph_secret_hex")),
            memoVec.getLong("amount").toULong(),
            hexToBytes(memoVec.getString("mint_hex"))
        )
        assertEquals(memoVec.getString("memo_90_hex"), bytesToHex(enc.memo90))
        assertEquals(memoVec.getString("commitment_hex"), bytesToHex(enc.commitment))

        val dec = decryptAndVerifyMemoEntry(fvk, enc.memo90, enc.commitment)
        assertNotNull(dec)
        assertEquals(memoVec.getLong("amount").toULong(), dec.amount)

        val bobVpk = hexToBytes(v.getJSONObject("bob").getString("view_pk_hex"))
        val dynM = prepareDynamicSwapMemo(bobVpk, ByteArray(32) { 0x44 })
        assertEquals(memoVec.getString("dyn_head_34_hex"), bytesToHex(dynM.dynHead34))
        assertEquals(memoVec.getString("dyn_mask_56_hex"), bytesToHex(dynM.dynMask56))

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
        val ctxPriv = computeJoinsplitCtxHashFfi(
            FfiJoinSplitCtxHashParams(
                programId = pid,
                poolId = 0u,
                outLaneId = 2u,
                outputMask = 7u,
                assetMode = 0u,
                unwrapWsol = false,
                recipient = null,
                relayerFeeRecipient = null,
                publicAssetId = ByteArray(32),
                publicAmountOut = 0uL,
                relayerFeeAmount = 0uL,
                memosBytes = enc.memo90
            )
        )
        assertEquals(
            v.getJSONObject("ctx_hashes").getString("joinsplit_private_ctx_hash_hex"),
            bytesToHex(ctxPriv)
        )

        val ps = decodePoolStateAccount(hexToBytes(v.getJSONObject("pool_state").getString("raw_hex")))
        assertEquals(4u.toUByte(), ps.activeLanes)
        assertEquals(8uL, ps.ckptInterval)

        val ck = decodeRootCheckpointAccount(hexToBytes(v.getString("checkpoint_raw_hex")))
        assertEquals(13u.toUShort(), ck.slotIdx)
        assertEquals(6uL, ck.laneCounts[2])
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
        val solAsset = hexToBytes(v.getJSONObject("asset_ids").getString("native_sol_asset_id_hex"))
        val w = java.io.ByteArrayOutputStream(4611)
        w.write(hexToBytes(g16.getString("super_root_hex")))
        w.write(solAsset)
        w.write(ByteArray(32))
        w.write(u64Le(0L))
        w.write(u64Le(0L))
        w.write(ctxPriv)
        w.write(1) // omit_nf1 = true

        // Input 0: real note at lane 2, leaf 5
        w.write(alice.spendSk)
        w.write(enc.tweak)
        w.write(solAsset)
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
        w.write(solAsset)
        w.write(u64Le(0L))
        w.write(u64Be32(0x5555L))
        w.write(1) // is_dummy = true
        w.write(ByteArray(20 + 20 * 3 * 32))

        // Outputs 0, 1, 2
        w.write(hexToBytes("297407e33a8667d5d8235b00a22b34f66113f3d1b9c5486704f12647a0ee1041"))
        w.write(solAsset)
        w.write(u64Le(1_000_000L))
        w.write(u64Be32(0x201L))

        w.write(hexToBytes("20944e988ecb9bf1ad2edbbc8b782ff1695fcd197058948fdf9ef6426fa55528"))
        w.write(solAsset)
        w.write(u64Le(500_000L))
        w.write(u64Be32(0x202L))

        w.write(ByteArray(32))
        w.write(solAsset)
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
    }
}
