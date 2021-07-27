package com.prongbang.rijndaelcrypto

import java.io.UnsupportedEncodingException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

/**
 * RFC 2898 password derivation compatible with .NET Rfc2898DeriveBytes class.
 */
class Rfc2898DeriveBytes(password: ByteArray?, salt: ByteArray?, iterations: Int) {
	private val _hmacSha1: Mac
	private val _salt: ByteArray
	private val _iterationCount: Int
	private var _buffer = ByteArray(20)
	private var _bufferStartIndex = 0
	private var _bufferEndIndex = 0
	private var _block = 1
	/**
	 * Creates new instance.
	 *
	 * @param password   The password used to derive the key.
	 * @param salt       The key salt used to derive the key.
	 * @param iterations The number of iterations for the operation.
	 * @throws NoSuchAlgorithmException     HmacSHA1 algorithm cannot be found.
	 * @throws InvalidKeyException          Salt must be 8 bytes or more. -or- Password cannot be null.
	 * @throws UnsupportedEncodingException UTF-8 encoding is not supported.
	 */
	/**
	 * Creates new instance.
	 *
	 * @param password The password used to derive the key.
	 * @param salt     The key salt used to derive the key.
	 * @throws NoSuchAlgorithmException     HmacSHA1 algorithm cannot be found.
	 * @throws InvalidKeyException          Salt must be 8 bytes or more. -or- Password cannot be null.
	 * @throws UnsupportedEncodingException UTF-8 encoding is not supported.
	 */
	@JvmOverloads
	constructor(password: String, salt: ByteArray?, iterations: Int = 0x3e8) : this(
			password.toByteArray(charset("UTF8")), salt, iterations) {
	}

	/**
	 * Returns a pseudo-random key from a password, salt and iteration count.
	 *
	 * @param count Number of bytes to return.
	 * @return Byte array.
	 */
	fun GetBytes(count: Int): ByteArray {
		val result = ByteArray(count)
		var resultOffset = 0
		val bufferCount = _bufferEndIndex - _bufferStartIndex
		if (bufferCount > 0) { // if there is some data in buffer
			if (count < bufferCount) { // if there is enough data in buffer
				System.arraycopy(_buffer, _bufferStartIndex, result, 0, count)
				_bufferStartIndex += count
				return result
			}
			System.arraycopy(_buffer, _bufferStartIndex, result, 0, bufferCount)
			_bufferEndIndex = 0
			_bufferStartIndex = _bufferEndIndex
			resultOffset += bufferCount
		}
		while (resultOffset < count) {
			val needCount = count - resultOffset
			_buffer = func()
			if (needCount > 20) { // we one (or more) additional passes
				System.arraycopy(_buffer, 0, result, resultOffset, 20)
				resultOffset += 20
			} else {
				System.arraycopy(_buffer, 0, result, resultOffset, needCount)
				_bufferStartIndex = needCount
				_bufferEndIndex = 20
				return result
			}
		}
		return result
	}

	private fun func(): ByteArray {
		_hmacSha1.update(_salt, 0, _salt.size)
		var tempHash = _hmacSha1.doFinal(
				getBytesFromInt(_block))
		_hmacSha1.reset()
		val finalHash = tempHash
		for (i in 2.._iterationCount) {
			tempHash = _hmacSha1.doFinal(tempHash)
			for (j in 0..19) {
				finalHash[j] = (finalHash[j] xor tempHash[j])
			}
		}
		if (_block == 2147483647) {
			_block = -2147483648
		} else {
			_block += 1
		}
		return finalHash
	}

	companion object {
		private fun getBytesFromInt(i: Int): ByteArray {
			return byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(),
					(i ushr 8).toByte(), i.toByte())
		}
	}

	/**
	 * Creates new instance.
	 *
	 * @param password   The password used to derive the key.
	 * @param salt       The key salt used to derive the key.
	 * @param iterations The number of iterations for the operation.
	 * @throws NoSuchAlgorithmException HmacSHA1 algorithm cannot be found.
	 * @throws InvalidKeyException      Salt must be 8 bytes or more. -or- Password cannot be null.
	 */
	init {
		if (salt == null || salt.size < 8) {
			throw InvalidKeyException("Salt must be 8 bytes or more.")
		}
		if (password == null) {
			throw InvalidKeyException("Password cannot be null.")
		}
		_salt = salt
		_iterationCount = iterations
		_hmacSha1 = Mac.getInstance("HmacSHA1")
		_hmacSha1.init(SecretKeySpec(password, "HmacSHA1"))
	}
}