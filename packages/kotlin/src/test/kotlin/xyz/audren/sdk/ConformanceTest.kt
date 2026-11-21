package xyz.audren.sdk

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConformanceTest {
    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun loadVectors(): JSONObject {
        val file = File("../../spec/test-vectors.json").canonicalFile
        require(file.exists()) { "Missing canonical test vectors at ${file.path}" }
        return JSONObject(file.readText())
    }

    @Test
    fun allSixBuildingBlocksMatchCanonicalVectorsAndBuildProofs() {
        val v = loadVectors()

        // 1. Keys, Sub-Accounts, Addresses, FVK & Asset Generators
        val pid = programId()
        assertEquals(v.getString("program_id"), pid)

        val aliceJson = v.getJSONObject("alice")
        val aliceSeed = hexToBytes(aliceJson.getString("seed_hex"))
        val alice = deriveKeysFromSeed(aliceSeed)
        assertEquals(aliceJson.getString("spend_sk_hex"), bytesToHex(alice.spendSk))
        assertEquals(aliceJson.getString("spend_pk_hex"), bytesToHex(alice.spendPk))
        assertEquals(aliceJson.getString("view_sk_hex"), bytesToHex(alice.viewSk))
        assertEquals(aliceJson.getString("view_pk_hex"), bytesToHex(alice.viewPk))
        assertEquals(aliceJson.getString("address"), alice.address)

        val parsed = parseAudrenAddress(alice.address)
        assertContentEquals(alice.spendPk, parsed.spendPk)
        assertContentEquals(alice.viewPk, parsed.viewPk)
        assertEquals(alice.address, formatAudrenAddress(parsed.spendPk, parsed.viewPk))

        val fvk = exportFullViewingKey(aliceSeed, 0u)
        val expectedFvk = JSONObject(aliceJson.getString("full_viewing_key_json"))
        assertEquals(expectedFvk.getInt("version").toUByte(), fvk.version)
        assertEquals(expectedFvk.getString("spend_pk_b58"), fvk.spendPkB58)
        assertEquals(expectedFvk.getString("view_sk_b58"), fvk.viewSkB58)
        assertEquals(expectedFvk.getString("view_pk_b58"), fvk.viewPkB58)

        val subs = v.getJSONArray("alice_subaccounts")
        for (i in 0 until subs.length()) {
            val sub = subs.getJSONObject(i)
            val derived = deriveSubaccountKeys(aliceSeed, sub.getInt("account_index").toUInt())
            assertEquals(sub.getString("spend_sk_hex"), bytesToHex(derived.spendSk))
            assertEquals(sub.getString("spend_pk_hex"), bytesToHex(derived.spendPk))
            assertEquals(sub.getString("address"), derived.address)
        }

        val gens = v.getJSONObject("asset_generators")
        assertEquals(
            gens.getString("native_sol_gen_hex"),
            bytesToHex(assetGenerator(ByteArray(32))),
        )

        // 2. Canonical PDAs & Account Decoders
        val pdas = v.getJSONObject("pdas")
        assertEquals(pdas.getJSONObject("pool").getString("address"), derivePoolPda(0u, pid).address)
        assertEquals(pdas.getJSONObject("pool").getInt("bump").toUByte(), derivePoolPda(0u, pid).bump)
        assertEquals(
            pdas.getJSONObject("epoch_page_0").getString("address"),
            deriveEpochPagePda(0u, 0uL, pid).address,
        )
        assertEquals(
            pdas.getJSONObject("epoch_page_lane1_seq0").getString("address"),
            deriveEpochPagePda(0u, 1uL shl 56, pid).address,
        )
        assertEquals(pdas.getJSONObject("sol_vault").getString("address"), deriveSolVaultPda(0u, pid).address)
        assertEquals(pdas.getJSONObject("vault_auth").getString("address"), deriveVaultAuthPda(0u, pid).address)
        assertEquals(pdas.getJSONObject("page_rent_vault").getString("address"), derivePageRentVaultPda(0u, pid).address)
        assertEquals(pdas.getJSONObject("swap_escrow_0").getString("address"), deriveSwapEscrowPda(0u, 0u, pid).address)
        assertEquals(pdas.getJSONObject("lane_1").getString("address"), deriveLanePda(0u, 1u, pid).address)
        assertEquals(pdas.getJSONObject("lane_rent_vault_1").getString("address"), deriveLaneRentVaultPda(0u, 1u, pid).address)
        assertEquals(
            pdas.getJSONObject("proof_buffer").getString("address"),
            deriveProofBufferPda(
                pdas.getString("proof_buffer_authority"),
                pdas.getLong("proof_buffer_nonce").toULong(),
                pid,
            ).address,
        )

        val psJson = v.getJSONObject("pool_state")
        val ps = decodePoolState(hexToBytes(psJson.getString("raw_hex")))
        assertEquals(psJson.getInt("version").toUByte(), ps.version)
        assertEquals(psJson.getInt("bump").toUByte(), ps.bump)
        assertEquals(psJson.getInt("mode").toUByte(), ps.mode)
        assertEquals(psJson.getBoolean("paused"), ps.paused)
        assertEquals(psJson.getLong("total_notes").toULong(), ps.totalNotes)
        assertEquals(psJson.getLong("total_spends").toULong(), ps.totalSpends)
        assertEquals(psJson.getInt("active_lanes").toUByte(), ps.activeLanes)

        // 3. Scanner & Note Decryption
        val epJson = v.getJSONObject("epoch_page")
        val sliceCfg = pageScanDataSlice()
        assertEquals(epJson.getInt("scan_offset").toUInt(), sliceCfg.offset)
        assertEquals(epJson.getInt("scan_length").toUInt(), sliceCfg.length)

        val pageBytes = hexToBytes(epJson.getString("page_hex"))
        val hdr = decodeEpochPageHeader(pageBytes)
        assertEquals(epJson.getInt("count").toUByte(), hdr.count)
        assertEquals(epJson.getBoolean("closed"), hdr.closed)
        assertEquals(epJson.getLong("created_slot").toULong(), hdr.createdSlot)
        assertEquals(epJson.getLong("closed_slot").toULong(), hdr.closedSlot)

        val hits = scanPageDataslice(
            0uL,
            hexToBytes(epJson.getString("scan_slice_hex")),
            alice.spendPk,
            alice.viewSk,
        )
        val expectedHits = epJson.getJSONArray("matched_slots")
        assertEquals(expectedHits.length(), hits.size)
        assertEquals(expectedHits.getInt(0).toByte(), hits[0])

        val notes = scanEpochPage(0u, pageBytes, alice.spendSk, alice.spendPk, alice.viewSk, pid)
        assertEquals(1, notes.size)
        val note = notes[0]
        val noteJson = epJson.getJSONObject("alice_note")
        assertEquals(noteJson.getInt("slot_index").toUByte(), note.slotIndex)
        assertEquals(noteJson.getLong("amount").toULong(), note.amount)
        assertEquals(noteJson.getString("stealth_pk_hex"), bytesToHex(note.stealthPk))
        assertEquals(noteJson.getString("asset_tag_hex"), bytesToHex(note.assetTag))
        assertEquals(noteJson.getString("commitment_hex"), bytesToHex(note.commitment))
        assertEquals(noteJson.getString("nullifier_hex"), bytesToHex(assertNotNull(note.nullifier)))
        assertEquals(noteJson.getString("nullifier_pda"), note.nullifierPda)

        // 4. Local ZK Proof Generation (Deposit, Transfer m=5, ProofBuffer, Withdraw)
        val payer = pdas.getString("proof_buffer_authority")
        val bobAddr = v.getJSONObject("bob").getString("address")

        val depIx = buildDepositInstruction(
            FfiDepositParams(
                programId = pid,
                depositor = payer,
                poolId = 0u,
                activePageId = 1uL,
                recipientAddress = bobAddr,
                mint32 = ByteArray(32),
                grossAmount = 500_000uL,
                netAmount = 500_000uL,
                tokenProgram = null,
                depositorAta = null,
                vaultAta = null,
            ),
        )
        assertEquals(2.toByte(), depIx.data[0])

        val xferIx = buildTransferInstruction(
            FfiTransferParams(
                programId = pid,
                payer = payer,
                poolId = 0u,
                outPageId = 1uL,
                inputPageIds = listOf(0uL),
                inputPagesBytes = listOf(pageBytes),
                inputNote = note,
                secretIndex = note.slotIndex.toUInt(),
                recipientAddress = bobAddr,
                changeAddress = alice.address,
                payAmount = 900_000uL,
                auditorPk32 = null,
            ),
        )
        assertEquals(3.toByte(), xferIx.data[0])
        assertTrue(xferIx.data.size > 2_000)

        val plan = buildBufferedExecutionPlan(42uL, xferIx)
        assertTrue(plan.uploadChunks.size >= 3)
        assertEquals(9.toByte(), plan.executeIx.data[0])

        val wdIx = buildWithdrawInstruction(
            FfiWithdrawParams(
                programId = pid,
                payer = payer,
                poolId = 0u,
                outPageId = 1uL,
                inputPageIds = listOf(0uL),
                inputPagesBytes = listOf(pageBytes),
                inputNote = note,
                secretIndex = note.slotIndex.toUInt(),
                recipientAccount = payer,
                changeAddress = alice.address,
                amount = 1_000_000uL,
                splTokenProgram = null,
                auditorPk32 = null,
            ),
        )
        assertEquals(6.toByte(), wdIx.data[0])
        assertTrue(wdIx.data.size > 1_800)

        // 5. Selective Disclosure & Institutional Auditor Decrypt
        val sd = createSelectiveDisclosureProof(note)
        assertTrue(verifySelectiveDisclosureProof(sd))
        assertTrue(verifySelectiveDisclosureOnPage(sd, pageBytes))

        val tampered = sd.copy(amount = sd.amount + 1uL)
        assertFalse(verifySelectiveDisclosureProof(tampered))
        assertFalse(verifySelectiveDisclosureOnPage(tampered, pageBytes))

        val audJson = v.getJSONObject("auditor")
        val aud = deriveAuditorKeypair(hexToBytes(audJson.getString("auditor_seed_hex")))
        assertEquals(audJson.getString("auditor_pk_hex"), bytesToHex(aud.auditorPk))
        val dec = auditorDecryptNote(
            aud.auditorSk,
            hexToBytes(audJson.getString("elgamal_s1_hex")),
            hexToBytes(audJson.getString("elgamal_s2_hex")),
            hexToBytes(audJson.getString("elgamal_m1_hex")),
            hexToBytes(audJson.getString("elgamal_m2_hex")),
        )
        assertEquals(audJson.getString("expected_spent_pk_hex"), bytesToHex(dec.spentStealthPk))
        assertEquals(audJson.getString("expected_asset_gen_hex"), bytesToHex(dec.assetGenerator))

        // 6. Router & Relayer
        assertEquals(v.getString("jupiter_cpi_excluded_dexes"), jupiterCpiExcludedDexes().joinToString(","))
        assertEquals("https://relay.audren.xyz", defaultRelayUrl())
    }
}
