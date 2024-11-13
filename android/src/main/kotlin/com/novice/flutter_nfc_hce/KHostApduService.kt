package com.novice.flutter_nfc_hce

import android.annotation.SuppressLint
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import java.io.*
import java.math.BigInteger

class KHostApduService : HostApduService() {

    private val TAG = "HostApduService"

    // ISO7816-4 Constants
    private object ISO7816 {
        // Class byte (CLA)
        const val CLA_ISO7816 = 0x00.toByte()
        
        // Instruction byte (INS)
        const val INS_SELECT = 0xA4.toByte()
        const val INS_READ_BINARY = 0xB0.toByte()
        const val INS_UPDATE_BINARY = 0xD6.toByte()
        
        // Parameter bytes (P1, P2)
        const val P1_SELECT_BY_DF_NAME = 0x04.toByte()
        const val P2_SELECT_BY_DF_NAME = 0x00.toByte()
        
        // Response Status Words
        val SW_NO_ERROR = byteArrayOf(0x90.toByte(), 0x00.toByte())
        val SW_FILE_NOT_FOUND = byteArrayOf(0x6A.toByte(), 0x82.toByte())
        val SW_INCORRECT_P1P2 = byteArrayOf(0x6A.toByte(), 0x86.toByte())
        val SW_INS_NOT_SUPPORTED = byteArrayOf(0x6D.toByte(), 0x00.toByte())
        val SW_CLA_NOT_SUPPORTED = byteArrayOf(0x6E.toByte(), 0x00.toByte())
        val SW_WRONG_LENGTH = byteArrayOf(0x67.toByte(), 0x00.toByte())
        val SW_SECURITY_STATUS_NOT_SATISFIED = byteArrayOf(0x69.toByte(), 0x82.toByte())
        val SW_CONDITIONS_NOT_SATISFIED = byteArrayOf(0x69.toByte(), 0x85.toByte())
    }

    // NDEF Application constants
    private val NDEF_AID = byteArrayOf(
        0xD2.toByte(), 0x76.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x85.toByte(), 0x01.toByte(), 0x01.toByte()
    )
    
    private val CC_FILE_ID = byteArrayOf(0xE1.toByte(), 0x03.toByte())
    private val NDEF_FILE_ID = byteArrayOf(0xE1.toByte(), 0x04.toByte())
    
    private var isIso7816Mode = false
    private var selectedAid: ByteArray? = null
    private var ndefCapabilityContainer: ByteArray? = null
    private var ndefData: ByteArray? = null
    private var ndefFileLength: ByteArray? = null

    override fun onCreate() {
        super.onCreate()
        setupNdefCapabilityContainer()
        Log.i(TAG, "KHostApduService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.hasExtra("content") == true) {
            val content = intent.getStringExtra("content")!!
            val mimeType = intent.getStringExtra("mimeType")!!
            val persistMessage = intent.getBooleanExtra("persistMessage", true)
            isIso7816Mode = intent.getBooleanExtra("iso7816Mode", false)

            if (persistMessage) {
                writeNdefMessageToFile(this, content)
            }

            setupNdefMessage(content, mimeType)
            Log.i(TAG, "Service started with content: $content, ISO7816 mode: $isIso7816Mode")
        }
        return Service.START_REDELIVER_INTENT
    }

    private fun setupNdefMessage(content: String, mimeType: String) {
        val ndefRecord = createNdefRecord(content, mimeType, NDEF_FILE_ID)
        val ndefMessage = NdefMessage(ndefRecord)
        ndefData = ndefMessage.toByteArray()
        ndefFileLength = fillByteArrayToFixedDimension(
            BigInteger.valueOf(ndefData!!.size.toLong()).toByteArray(),
            2
        )
        Log.i(TAG, "NDEF message setup complete, length: ${ndefData!!.size}")
    }

    private fun setupNdefCapabilityContainer() {
        ndefCapabilityContainer = byteArrayOf(
            0x00.toByte(), 0x0F.toByte(),       // CCLEN: Length of CC file
            0x20.toByte(),                      // Mapping Version 2.0
            0x00.toByte(), 0x3B.toByte(),       // MLe maximum
            0x00.toByte(), 0x34.toByte(),       // MLc maximum
            0x04.toByte(),                      // T field of the NDEF File Control TLV
            0x06.toByte(),                      // L field of the NDEF File Control TLV
            0xE1.toByte(), 0x04.toByte(),       // File Identifier
            0x00.toByte(), 0xFF.toByte(),       // Maximum NDEF file size
            0x00.toByte(),                      // Read access without security
            0xFF.toByte()                       // Write access without security
        )
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        if (commandApdu.isEmpty()) return ISO7816.SW_WRONG_LENGTH
        
        Log.i(TAG, "Received APDU: ${commandApdu.toHex()}")
        
        return if (isIso7816Mode) {
            processIso7816CommandApdu(commandApdu)
        } else {
            processLegacyCommandApdu(commandApdu)
        }
    }

    private fun processIso7816CommandApdu(commandApdu: ByteArray): ByteArray {
        if (commandApdu.size < 4) return ISO7816.SW_WRONG_LENGTH

        val cla = commandApdu[0]
        val ins = commandApdu[1]
        val p1 = commandApdu[2]
        val p2 = commandApdu[3]

        // Verify CLA byte
        if (cla != ISO7816.CLA_ISO7816) {
            Log.w(TAG, "Invalid CLA byte: ${cla.toHex()}")
            return ISO7816.SW_CLA_NOT_SUPPORTED
        }

        return when (ins) {
            ISO7816.INS_SELECT -> handleSelect(commandApdu)
            ISO7816.INS_READ_BINARY -> handleReadBinary(commandApdu)
            ISO7816.INS_UPDATE_BINARY -> handleUpdateBinary(commandApdu)
            else -> {
                Log.w(TAG, "Unsupported INS byte: ${ins.toHex()}")
                ISO7816.SW_INS_NOT_SUPPORTED
            }
        }
    }

    private fun handleSelect(commandApdu: ByteArray): ByteArray {
        if (commandApdu.size < 5) return ISO7816.SW_WRONG_LENGTH
        
        val p1 = commandApdu[2]
        val p2 = commandApdu[3]
        val lc = commandApdu[4].toInt() and 0xFF
        
        if (commandApdu.size < 5 + lc) return ISO7816.SW_WRONG_LENGTH

        // Extract AID from command APDU
        val aid = commandApdu.slice(5 until 5 + lc).toByteArray()
        
        return when {
            p1 == ISO7816.P1_SELECT_BY_DF_NAME && p2 == ISO7816.P2_SELECT_BY_DF_NAME -> {
                if (aid.contentEquals(NDEF_AID)) {
                    selectedAid = aid
                    Log.i(TAG, "NDEF AID selected successfully")
                    ISO7816.SW_NO_ERROR
                } else {
                    Log.w(TAG, "Invalid AID selection: ${aid.toHex()}")
                    ISO7816.SW_FILE_NOT_FOUND
                }
            }
            else -> {
                Log.w(TAG, "Invalid P1P2 for SELECT: ${p1.toHex()}${p2.toHex()}")
                ISO7816.SW_INCORRECT_P1P2
            }
        }
    }

    private fun handleReadBinary(commandApdu: ByteArray): ByteArray {
        if (selectedAid == null) return ISO7816.SW_CONDITIONS_NOT_SATISFIED

        val p1 = commandApdu[2]
        val p2 = commandApdu[3]
        val offset = (p1.toInt() shl 8) or (p2.toInt() and 0xFF)
        val le = if (commandApdu.size >= 5) commandApdu[4].toInt() and 0xFF else 0

        val fileData = when {
            offset == 0 && p1.toInt() == 0 && p2.toInt() == 0 -> ndefCapabilityContainer
            else -> ndefData
        } ?: return ISO7816.SW_FILE_NOT_FOUND

        if (offset >= fileData.size) return ISO7816.SW_INCORRECT_P1P2

        val maxLength = minOf(le, fileData.size - offset)
        val response = ByteArray(maxLength + 2)
        System.arraycopy(fileData, offset, response, 0, maxLength)
        System.arraycopy(ISO7816.SW_NO_ERROR, 0, response, maxLength, 2)

        Log.i(TAG, "Read Binary successful, offset: $offset, length: $maxLength")
        return response
    }

    private fun handleUpdateBinary(commandApdu: ByteArray): ByteArray {
        if (selectedAid == null) return ISO7816.SW_CONDITIONS_NOT_SATISFIED
        if (commandApdu.size < 5) return ISO7816.SW_WRONG_LENGTH

        val p1 = commandApdu[2]
        val p2 = commandApdu[3]
        val lc = commandApdu[4].toInt() and 0xFF
        val offset = (p1.toInt() shl 8) or (p2.toInt() and 0xFF)

        if (commandApdu.size < 5 + lc) return ISO7816.SW_WRONG_LENGTH
        if (offset >= (ndefData?.size ?: 0)) return ISO7816.SW_INCORRECT_P1P2

        // In this implementation, we don't actually update the binary data
        // You would need to implement the actual data update logic here
        Log.i(TAG, "Update Binary called but not implemented")
        return ISO7816.SW_CONDITIONS_NOT_SATISFIED
    }

    private fun processLegacyCommandApdu(commandApdu: ByteArray): ByteArray {
        // Legacy NDEF handling - kept for backward compatibility
        when {
            commandApdu.contentEquals(APDU_SELECT) -> {
                Log.i(TAG, "Legacy SELECT NDEF application")
                return ISO7816.SW_NO_ERROR
            }
            commandApdu.contentEquals(SELECT_CC_FILE) -> {
                Log.i(TAG, "Legacy SELECT CC")
                return ISO7816.SW_NO_ERROR
            }
            commandApdu.contentEquals(SELECT_NDEF_FILE) -> {
                Log.i(TAG, "Legacy SELECT NDEF")
                return ISO7816.SW_NO_ERROR
            }
            isReadBinaryCommand(commandApdu) -> {
                return handleLegacyReadBinary(commandApdu)
            }
        }
        return ISO7816.SW_INS_NOT_SUPPORTED
    }

    private fun isReadBinaryCommand(commandApdu: ByteArray): Boolean {
        return commandApdu.size >= 2 && 
               commandApdu[0] == 0x00.toByte() && 
               commandApdu[1] == 0xB0.toByte()
    }

    private fun handleLegacyReadBinary(commandApdu: ByteArray): ByteArray {
        val p1 = commandApdu[2]
        val p2 = commandApdu[3]
        val length = if (commandApdu.size >= 5) commandApdu[4].toInt() else 0
        val offset = (p1.toInt() shl 8) or (p2.toInt() and 0xFF)

        val fileData = when {
            offset == 0 -> ndefCapabilityContainer
            else -> ndefData
        } ?: return ISO7816.SW_FILE_NOT_FOUND

        val maxLength = minOf(length, fileData.size - offset)
        val response = ByteArray(maxLength + 2)
        System.arraycopy(fileData, offset, response, 0, maxLength)
        System.arraycopy(ISO7816.SW_NO_ERROR, 0, response, maxLength, 2)

        return response
    }

    override fun onDeactivated(reason: Int) {
        Log.i(TAG, "Connection deactivated, reason: $reason")
        selectedAid = null
    }

    // Helper methods for NDEF message handling
    private fun createNdefRecord(content: String, mimeType: String, id: ByteArray): NdefRecord {
        return if (mimeType == "text/plain") {
            createTextRecord("en", content, id)
        } else {
            NdefRecord(
                NdefRecord.TNF_MIME_MEDIA,
                mimeType.toByteArray(charset("US-ASCII")),
                id,
                content.toByteArray(charset("UTF-8"))
            )
        }
    }

    private fun createTextRecord(language: String, text: String, id: ByteArray): NdefRecord {
        val languageBytes = language.toByteArray(charset("US-ASCII"))
        val textBytes = text.toByteArray(charset("UTF-8"))
        val recordPayload = ByteArray(1 + languageBytes.size + textBytes.size)

        recordPayload[0] = languageBytes.size.toByte()
        System.arraycopy(languageBytes, 0, recordPayload, 1, languageBytes.size)
        System.arraycopy(textBytes, 0, recordPayload, 1 + languageBytes.size, textBytes.size)

        return NdefRecord(NdefRecord.TNF_WELL_KNOWN, NdefRecord.RTD_TEXT, id, recordPayload)
    }

    private fun fillByteArrayToFixedDimension(array: ByteArray, fixedSize: Int): ByteArray {
        if (array.size == fixedSize) return array
        
        val result = ByteArray(fixedSize)
        System.arraycopy(array, 0, result, result.size - array.size, array.size)
        return result
    }
    //2023.09.16 modify
    companion object {
        private val READ_BLOCK_SIZE: Int = 100
        @SuppressLint("LongLogTag")
        @JvmStatic
        fun readNdefMessageFromFile(context: Context): String? {
            var ndefMessage: String? = "Hello world"

            try {
                val fileIn: FileInputStream = context.openFileInput("NdefMessage.txt")
                val InputRead = InputStreamReader(fileIn)
                val inputBuffer = CharArray(READ_BLOCK_SIZE)
                var charRead: Int
                while (InputRead.read(inputBuffer).also { charRead = it } > 0) {
                    // char to string conversion
                    val readstring = String(inputBuffer, 0, charRead)
                    ndefMessage = readstring
                }
                InputRead.close()

                Log.i("readNdefMessageFromFile()", "Read a message '"+ ndefMessage +"' from NdefMessage.txt.")
            } catch (e: java.lang.Exception) {
                e.printStackTrace()
            }

            return ndefMessage
        }

        @SuppressLint("LongLogTag")
        @JvmStatic
        fun writeNdefMessageToFile(context: Context, ndefMessage: String) {
            try {
                val fileout: FileOutputStream = context.openFileOutput("NdefMessage.txt", MODE_PRIVATE)
                val outputWriter = OutputStreamWriter(fileout)
                outputWriter.write(ndefMessage)
                outputWriter.close()

                Log.i("writeNdefMessageToFile()", "Wrote a message to NdefMessage.txt.")
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        @JvmStatic
        fun deleteNdefMessageFile(context: Context) {
            try {
                context.deleteFile("NdefMessage.txt")
                Log.i("deleteNdefMessageFile()", "The NdefMessage.txt has been deleted.")
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
}
