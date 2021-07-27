package com.prongbang.rijndaelcrypto

import org.bouncycastle.crypto.engines.RijndaelEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.paddings.ZeroBytePadding
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.util.encoders.Base64

class RijndaelCryptography : Cryptography {

	override fun encrypt(plainText: String, secret: String): String {
		throw Throwable("Unsupported")
	}

	override fun decrypt(cipherText: String, secret: String): String {
		// Get the complete stream of bytes that represent:
		// [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
		val cipherTextByte = Base64.decode(cipherText)
		// Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
		val saltBytes = cipherTextByte.copyOfRange(0, KEY_SIZE / 8)
		// Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
		val ivBytes = cipherTextByte.copyOfRange(KEY_SIZE / 8, cipherTextByte.size - (KEY_SIZE / 8))
		// Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
		val resultBytes = cipherTextByte.copyOfRange(((KEY_SIZE / 8) * 2), cipherTextByte.size)

		val password = Rfc2898DeriveBytes(secret, saltBytes, DERIVATION_ITERATIONS)
		val keyBytes = password.GetBytes(KEY_SIZE / 8)

		val rijndaelEngine = RijndaelEngine(KEY_SIZE)
		val keyParam = KeyParameter(keyBytes)
		val ivAndKey = ParametersWithIV(keyParam, ivBytes, 0, 32)
		val cipher = PaddedBufferedBlockCipher(CBCBlockCipher(rijndaelEngine), ZeroBytePadding())
		cipher.init(false, ivAndKey)
		val decrypted = ByteArray(cipher.getOutputSize(resultBytes.size))
		val oLen = cipher.processBytes(resultBytes, 0, resultBytes.size, decrypted, 0)
		cipher.doFinal(decrypted, oLen)

		var plaintext = String(decrypted)
		plaintext = plaintext.replace("\\u000b".toRegex(), "")
				.replace("\\u0014".toRegex(), "")
		return plaintext
	}

	companion object {
		private const val DERIVATION_ITERATIONS = 1000
		private const val KEY_SIZE = 256
	}
}