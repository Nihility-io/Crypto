import { scryptAsync } from "@noble/hashes/scrypt.js"
import { config } from "./config.ts"
import { CryptoURL, KeyAlgorithm, randomBytes, toBytes, UnsupportedKeyAlgorithmError } from "./mod.ts"

/**
 * Combines a random base key with an optional password to create a new key
 * @param baseKey Random encryption key
 * @param password Optional password to combine with the key
 * @returns New key
 */
export function combineBaseKeyWithPassword(baseKey: Uint8Array, password: string): Uint8Array {
	if (!password || password.length === 0) {
		return baseKey // No password, return the key as is
	}

	// If password is set, append it to the key
	const pwData = toBytes(password)
	const newKeyArray = new Uint8Array(baseKey.length + password.length)
	newKeyArray.set(baseKey, 0)
	newKeyArray.set(pwData, baseKey.length)
	return newKeyArray
}

/**
 * Generates a new encryption key based on a random encryption key and an optional password
 * @param passphrase Passphrase used to encrypt the data
 * @param cryptoURL Crypto parameters containing the key algorithm and other settings
 * @returns Derived key
 */
export function deriveKey(passphrase: string | Uint8Array, cryptoURL: CryptoURL): Promise<CryptoKey | Uint8Array> {
	switch (cryptoURL.keyAlgorithm) {
		case KeyAlgorithm.PBKDF2:
			return deriveKeyPBKDF2(passphrase, cryptoURL)
		case KeyAlgorithm.Scrypt:
			return deriveKeyScrypt(passphrase, cryptoURL)
		default:
			throw new UnsupportedKeyAlgorithmError(cryptoURL.keyAlgorithm)
	}
}

/**
 * Generates a new encryption key using PBKDF2 based on a random encryption key
 * @param passphrase Passphrase used to encrypt the data
 * @param cryptoURL Crypto parameters containing the key algorithm and other settings
 * @returns Derived key
 */
async function deriveKeyPBKDF2(passphrase: string | Uint8Array, cryptoURL: CryptoURL): Promise<CryptoKey> {
	// Import raw key
	const importedKey = await globalThis.crypto.subtle.importKey(
		"raw", // Only 'raw' is allowed
		typeof passphrase === "string" ? toBytes(passphrase) : passphrase, // Encryption key
		{ name: "PBKDF2" }, // Use PBKDF2 for key derivation
		false, // The key may not be exported
		["deriveKey"], // We may only use it for key derivation
	)

	// derive a stronger key for use with AES
	return globalThis.crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: cryptoURL.getBase58("salt", randomBytes(config.PBKDF2.saltLength)),
			iterations: cryptoURL.getNumber("iter", config.PBKDF2.iterations),
			hash: { name: cryptoURL.get("hash", config.PBKDF2.hash) },
		}, // Key algorithm
		importedKey,
		{
			name: "AES-GCM",
			length: 256,
		}, // Set what the key is intended to be used for
		true, // The key may be exported
		["encrypt", "decrypt"], // We may only use it for en- and decryption
	)
}

/**
 * Generates a new encryption key using Scrypt based on a random encryption key
 * @param passphrase Passphrase used to encrypt the data
 * @param cryptoURL Crypto parameters containing the key algorithm and other settings
 * @returns Derived key
 */
function deriveKeyScrypt(passphrase: string | Uint8Array, cryptoURL: CryptoURL): Promise<Uint8Array> {
	return scryptAsync(
		typeof passphrase === "string" ? toBytes(passphrase) : passphrase,
		cryptoURL.getBase58("salt", randomBytes(config.Scrypt.saltLength)),
		{
			N: cryptoURL.getNumber("n", config.Scrypt.N), // Cost factor
			r: cryptoURL.getNumber("r", config.Scrypt.r), // Block size
			p: cryptoURL.getNumber("p", config.Scrypt.p), // Parallelization
			dkLen: 32, // Key length
		},
	)
}
