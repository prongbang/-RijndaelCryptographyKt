package com.prongbang.rijndaelcrypto

interface Cryptography {
	fun encrypt(plainText: String, secret: String): String
	fun decrypt(cipherText: String, secret: String): String
}