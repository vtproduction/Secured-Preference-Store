package devliving.online.securedpreferencestore

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import devliving.online.securedpreferencestore.EncryptionManager.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal
import kotlin.experimental.xor

/**
 * Created by NienLe on 26,October,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */
class EncryptionManager2 {

    private val RSA_BIT_LENGTH = 2048
    private val AES_BIT_LENGTH = 256
    private val MAC_BIT_LENGTH = 256

    private val COMPAT_IV_LENGTH = 16

    private val DEFAULT_CHARSET = "UTF-8"
    private val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private val SSL_PROVIDER = "AndroidOpenSSL"
    private val BOUNCY_CASTLE_PROVIDER = "BC"
    private val RSA_KEY_ALIAS_NAME = "rsa_key"
    private val AES_KEY_ALIAS_NAME = "aes_key"
    private val MAC_KEY_ALIAS_NAME = "mac_key"
    private val OVERRIDING_KEY_ALIAS_PREFIX_NAME = "OverridingAlias"
    private val DEFAULT_KEY_ALIAS_PREFIX = "sps"



    private val KEY_ALGORITHM_AES = "AES"
    private val KEY_ALGORITHM_RSA = "RSA"

    private val BLOCK_MODE_ECB = "ECB"
    private val BLOCK_MODE_GCM = "GCM"
    private val BLOCK_MODE_CBC = "CBC"

    private val ENCRYPTION_PADDING_RSA_PKCS1 = "PKCS1Padding"
    private val ENCRYPTION_PADDING_PKCS7 = "PKCS7Padding"
    private val ENCRYPTION_PADDING_NONE = "NoPadding"
    private val MAC_ALGORITHM_HMAC_SHA256 = "HmacSHA256"
    private var IS_COMPAT_MODE_KEY_ALIAS_NAME = "data_in_compat"

    private var SHIFTING_KEY: ByteArray? = null
    private var RSA_KEY_ALIAS: String = ""
    private var AES_KEY_ALIAS: String =""
    private var MAC_KEY_ALIAS: String = ""
    private var mKeyAliasPrefix: String = ""
    private var IS_COMPAT_MODE_KEY_ALIAS: String = ""


    private val RSA_CIPHER = KEY_ALGORITHM_RSA + "/" +
            BLOCK_MODE_ECB + "/" +
            ENCRYPTION_PADDING_RSA_PKCS1
    private val AES_CIPHER_COMPAT = KEY_ALGORITHM_AES + "/" +
            BLOCK_MODE_CBC + "/" +
            ENCRYPTION_PADDING_PKCS7
    private val MAC_CIPHER = MAC_ALGORITHM_HMAC_SHA256

    private var mStore: KeyStore? = null
    private var aesKey: SecretKey? = null
    private var macKey: SecretKey? = null

    private var publicKey: RSAPublicKey? = null
    private var privateKey: RSAPrivateKey? = null
    private var mContext: Context? = null



    constructor(context: Context, keyAliasPrefix: String?, bitShiftingKey: ByteArray?){


        SHIFTING_KEY = bitShiftingKey
        mKeyAliasPrefix = keyAliasPrefix ?: DEFAULT_KEY_ALIAS_PREFIX
        IS_COMPAT_MODE_KEY_ALIAS = String.format("%s_%s", mKeyAliasPrefix, IS_COMPAT_MODE_KEY_ALIAS_NAME)
        RSA_KEY_ALIAS = String.format("%s_%s", mKeyAliasPrefix, RSA_KEY_ALIAS_NAME)
        AES_KEY_ALIAS = String.format("%s_%s", mKeyAliasPrefix, AES_KEY_ALIAS_NAME)
        MAC_KEY_ALIAS = String.format("%s_%s", mKeyAliasPrefix, MAC_KEY_ALIAS_NAME)
        mContext = context
        loadKeyStore()

        setup(context,  bitShiftingKey)
    }


    @Throws(NoSuchAlgorithmException::class, UnsupportedEncodingException::class)
    fun getHashed(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")

        val result = digest.digest(text.toByteArray(charset(DEFAULT_CHARSET)))

        return toHex(result)
    }

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class)
    internal fun loadKeyStore() {
        mStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        mStore!!.load(null)
    }


    @Throws(NoSuchPaddingException::class, InvalidKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, UnrecoverableEntryException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class, IOException::class)
    internal fun setup(context: Context,  seed: ByteArray?) {
        val keyGenerated = generateKey(context, seed)
        if (keyGenerated) {
            //store the alias prefix
        }

        loadKey()
    }

    @Throws(KeyStoreException::class, NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class, UnrecoverableEntryException::class, NoSuchPaddingException::class, InvalidKeyException::class, IOException::class)
    internal fun generateKey(context: Context, seed: ByteArray?): Boolean {
        var keyGenerated = false

        keyGenerated = generateRSAKeys(context, seed)
        loadRSAKeys()
        keyGenerated = generateFallbackAESKey(seed) || keyGenerated
        keyGenerated = generateMacKey(seed) || keyGenerated

        return keyGenerated
    }


    @SuppressLint("WrongConstant")
    @Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class, KeyStoreException::class)
    internal fun generateRSAKeys(context: Context, seed: ByteArray?): Boolean {
        if (!mStore!!.containsAlias(RSA_KEY_ALIAS)) {
            val keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER)

            val spec: KeyPairGeneratorSpec
            val start = Calendar.getInstance()
            //probable fix for the timezone issue
            start.add(Calendar.HOUR_OF_DAY, -26)

            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 100)

            spec = KeyPairGeneratorSpec.Builder(context)
                    .setAlias(RSA_KEY_ALIAS)
                    .setKeySize(RSA_BIT_LENGTH)
                    .setKeyType(KEY_ALGORITHM_RSA)
                    .setSerialNumber(BigInteger.ONE)
                    .setSubject(X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()

            if (seed != null && seed.size > 0) {
                val random = SecureRandom(seed)
                keyGen.initialize(spec, random)
            } else {
                keyGen.initialize(spec)
            }
            keyGen.generateKeyPair()

            return true
        }

        return false
    }


    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, NoSuchProviderException::class, InvalidKeyException::class, IOException::class)
    internal fun loadKey() {
        aesKey = getFallbackAESKey()
        macKey = getMacKey()
    }

    @Throws(KeyStoreException::class, UnrecoverableEntryException::class, NoSuchAlgorithmException::class)
    internal fun loadRSAKeys() {
        if (mStore!!.containsAlias(RSA_KEY_ALIAS) && mStore!!.entryInstanceOf(RSA_KEY_ALIAS, KeyStore.PrivateKeyEntry::class.java)) {
            val entry = mStore!!.getEntry(RSA_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
            publicKey = entry.certificate.publicKey as RSAPublicKey
            privateKey = entry.privateKey as RSAPrivateKey
        }
    }


    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, KeyStoreException::class, NoSuchProviderException::class, UnrecoverableEntryException::class)
    internal fun generateFallbackAESKey( seed: ByteArray?): Boolean {
        val key = getHashed(AES_KEY_ALIAS)

        if (!prefStore.contains(key)) {
            val keyGen = KeyGenerator.getInstance(KEY_ALGORITHM_AES)

            if (seed != null && seed.size > 0) {
                val random = SecureRandom(seed)
                keyGen.init(AES_BIT_LENGTH, random)
            } else {
                keyGen.init(AES_BIT_LENGTH)
            }

            val sKey = keyGen.generateKey()

            val shiftedEncodedKey = xorWithKey(sKey.encoded, SHIFTING_KEY)
            val encryptedData = RSAEncrypt(shiftedEncodedKey)

            val AESKey = base64Encode(encryptedData)
            val result = prefStore.edit().putString(key, AESKey).commit()
            val isCompatKey = getHashed(IS_COMPAT_MODE_KEY_ALIAS)
            prefStore.edit().putBoolean(isCompatKey, true).apply()
            return result
        }

        return false
    }

    fun base64Encode(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP)
    }

    fun base64Decode(text: String): ByteArray {
        return Base64.decode(text, Base64.NO_WRAP)
    }

    @Throws(NoSuchPaddingException::class, InvalidKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, UnrecoverableEntryException::class, IOException::class)
    internal fun generateMacKey(prefStore: SharedPreferences, seed: ByteArray?): Boolean {
        val key = getHashed(MAC_KEY_ALIAS)

        if (!prefStore.contains(key)) {
            val randomBytes = ByteArray(MAC_BIT_LENGTH / 8)
            val rng: SecureRandom
            if (seed != null && seed.size > 0) {
                rng = SecureRandom(seed)
            } else {
                rng = SecureRandom()
            }

            rng.nextBytes(randomBytes)

            val encryptedKey = RSAEncrypt(randomBytes)
            val macKey = base64Encode(encryptedKey)
            return prefStore.edit().putString(key, macKey).commit()
        }

        return false
    }

    private fun xorWithKey(a: ByteArray, key: ByteArray?): ByteArray {
        if (key == null || key.size == 0) return a

        val out = ByteArray(a.size)
        for (i in a.indices) {
            out[i] = (a[i] xor key[i % key.size]).toByte()
        }
        return out
    }

    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, NoSuchPaddingException::class, InvalidKeyException::class, IOException::class)
    internal fun RSAEncrypt(bytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(RSA_CIPHER, SSL_PROVIDER)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, cipher)
        cipherOutputStream.write(bytes)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidKeyException::class, IOException::class)
    internal fun RSADecrypt(bytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(RSA_CIPHER, SSL_PROVIDER)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        val cipherInputStream = CipherInputStream(ByteArrayInputStream(bytes), cipher)

        val values = ArrayList<Byte>()
        var nextByte = cipherInputStream.read()
        while (nextByte != -1){
            values.add(nextByte.toByte())
            nextByte = cipherInputStream.read()
        }

        val dbytes = ByteArray(values.size)
        for (i in dbytes.indices) {
            dbytes[i] = values[i]
        }

        cipherInputStream.close()
        return dbytes
    }


    @Throws(IOException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, NoSuchProviderException::class, NoSuchPaddingException::class)
    internal fun getFallbackAESKey(prefStore: SharedPreferences): SecretKey? {
        val key = getHashed(AES_KEY_ALIAS)

        val base64Value = prefStore.getString(key, null)
        if (base64Value != null) {
            val encryptedData = base64Decode(base64Value)
            val shiftedEncodedKey = RSADecrypt(encryptedData)
            val keyData = xorWithKey(shiftedEncodedKey, SHIFTING_KEY)

            return SecretKeySpec(keyData, "AES")
        }

        return null
    }


    @Throws(IOException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, NoSuchProviderException::class, NoSuchPaddingException::class)
    internal fun getMacKey(prefStore: SharedPreferences): SecretKey? {
        val key = getHashed(MAC_KEY_ALIAS)

        val base64 = prefStore.getString(key, null)
        if (base64 != null) {
            val encryptedKey = base64Decode(base64)
            val keyData = RSADecrypt(encryptedKey)

            return SecretKeySpec(keyData, MAC_CIPHER)
        }

        return null
    }


    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, IOException::class, BadPaddingException::class, NoSuchProviderException::class, IllegalBlockSizeException::class, InvalidAlgorithmParameterException::class)
    fun encrypt(bytes: ByteArray?): EncryptedData? {
        if (bytes != null && bytes.size > 0) {
            val IV = getIV()

            return encryptAESCompat(bytes, IV)

        }

        return null
    }

    @Throws(IOException::class, NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, NoSuchAlgorithmException::class, IllegalBlockSizeException::class, BadPaddingException::class, InvalidMacException::class, NoSuchProviderException::class, InvalidKeyException::class)
    fun decrypt(data: EncryptedData?): ByteArray? {
        return if (data != null && data.encryptedData != null) {
            decryptAESCompat(data)

        } else null

    }

    internal fun getIV(): ByteArray {
        val iv: ByteArray
        iv = ByteArray(COMPAT_IV_LENGTH)
        val rng = SecureRandom()
        rng.nextBytes(iv)
        return iv
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class, NoSuchProviderException::class, NoSuchPaddingException::class, InvalidAlgorithmParameterException::class, BadPaddingException::class, IllegalBlockSizeException::class, InvalidMacException::class)
    internal fun decryptAESCompat(encryptedData: EncryptedData): ByteArray {
        if (verifyMac(encryptedData.mac, encryptedData.dataForMacComputation)) {
            val c = getCipherAESCompat(encryptedData.iv!!, false)
            return c.doFinal(encryptedData.encryptedData)
        } else
            throw InvalidMacException()
    }

    @Throws(InvalidKeyException::class, NoSuchAlgorithmException::class)
    internal fun verifyMac(mac: ByteArray?, data: ByteArray?): Boolean {
        if (mac != null && data != null) {
            val actualMac = computeMac(data)

            if (actualMac.size != mac.size) {
                return false
            }
            var result = 0
            for (i in actualMac.indices) {
                result = result or (actualMac[i] xor mac[i]).toInt()
            }
            return result == 0
        }

        return false
    }


    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidKeyException::class, BadPaddingException::class, IllegalBlockSizeException::class, UnsupportedEncodingException::class, InvalidAlgorithmParameterException::class)
    internal fun encryptAESCompat(bytes: ByteArray, IV: ByteArray): EncryptedData {
        val c = getCipherAESCompat(IV, true)
        val result = EncryptedData()
        result.iv = c.getIV()
        result.encryptedData = c.doFinal(bytes)
        result.mac = computeMac(result.dataForMacComputation)

        return result
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    internal fun computeMac(data: ByteArray): ByteArray {
        val HmacSha256 = Mac.getInstance(MAC_CIPHER)
        HmacSha256.init(macKey)
        return HmacSha256.doFinal(data)
    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class)
    internal fun getCipherAESCompat(IV: ByteArray, modeEncrypt: Boolean): Cipher {
        val c = Cipher.getInstance(AES_CIPHER_COMPAT, BOUNCY_CASTLE_PROVIDER)
        c.init(if (modeEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, aesKey, IvParameterSpec(IV))

        return c
    }


    class EncryptedData {
        var iv: ByteArray? = null
        var encryptedData: ByteArray? = null
        var mac: ByteArray? = null

        /**
         * @return IV + CIPHER
         */
        val dataForMacComputation: ByteArray
            get() {
                val combinedData = ByteArray(iv!!.size + encryptedData!!.size)
                System.arraycopy(iv!!, 0, combinedData, 0, iv!!.size)
                System.arraycopy(encryptedData!!, 0, combinedData, iv!!.size, encryptedData!!.size)

                return combinedData
            }

        override fun toString(): String {
            return "EncryptedData{" +
                    "IV=" + Arrays.toString(iv) +
                    ", encryptedData=" + Arrays.toString(encryptedData) +
                    ", mac=" + Arrays.toString(mac) +
                    '}'.toString()
        }

        constructor() {
            iv = null
            encryptedData = null
            mac = null
        }

        constructor(IV: ByteArray, encryptedData: ByteArray, mac: ByteArray) {
            this.iv = IV
            this.encryptedData = encryptedData
            this.mac = mac
        }
    }

    inner class InvalidMacException : GeneralSecurityException("Invalid Mac, failed to verify integrity.")
}