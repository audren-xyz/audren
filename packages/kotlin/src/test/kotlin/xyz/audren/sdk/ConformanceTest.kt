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
    fun v2ConformanceVectorsMatchSpec() {
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

        // 2. Asset ID & 13 V2 PDAs
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
    }
}
