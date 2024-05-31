import { decodeBase64, encodeBase64 } from "@std/encoding/base64"

/**
 * Generates a random Uint8Array with a given length
 * @param length Number of bytes to return
 * @returns A Uint8Array with random bytes
 */
export const randomBytes = (length: number): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(length))

/**
 * Converts a raw string into a bytes
 * @param s String
 * @returns Bytes
 */
export const toBytes = (s: string): Uint8Array => new TextEncoder().encode(s)

/**
 * Converts bytes into a raw string
 * @param b Bytes
 * @returns String
 */
export const fromBytes = (b: Uint8Array): string => new TextDecoder().decode(b)

export enum EncryptionAlgorithm {
	AES256GCM = "AES256-GCM",
}

export interface EncryptedData {
	/** Used encryption algorithm */
	algorithm: EncryptionAlgorithm

	/** Base64 encoded initialization vector for encryption */
	iv: string

	/**  Base64 encoded salt for key generation */
	salt: string

	/** Actual encrypted data */
	data: string
}

/**
 * Encrypts the message using the given key and password
 * @param key Random encryption key (e.g. 256 bit (32 byte) for AES256-GCM)
 * @param password Optional encryption password which can be using in addition to the key
 * @param message Message to encrypt
 * @param algorithm Encryption algorithm (default: AES256-GCM)
 * @returns Encrypted data
 */
export const encrypt = async (
	key: Uint8Array,
	password: string,
	message: string,
	algorithm = EncryptionAlgorithm.AES256GCM,
): Promise<EncryptedData> => {
	if (algorithm !== EncryptionAlgorithm.AES256GCM) {
		throw new Error("unsupported encryption algorithm")
	}

	if (algorithm === EncryptionAlgorithm.AES256GCM && key.length !== 32) {
		throw new Error("invalid key length for AES256-GCM")
	}

	const iv = randomBytes(16)
	const salt = randomBytes(8)

	const k = await deriveAESKey(key, password, salt)
	const data = new Uint8Array(
		await window.crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv, additionalData: new Uint8Array() },
			k,
			toBytes(message),
		),
	)

	return {
		data: encodeBase64(data),
		iv: encodeBase64(iv),
		salt: encodeBase64(salt),
		algorithm,
	} as EncryptedData
}

/**
 * Decrypts the message using the given key and password
 * @param key Random encryption key (e.g. 256 bit (32 byte) for AES256-GCM)
 * @param password Optional encryption password which can be using in addition to the key
 * @param data Encrypted data
 * @returns Decrypted data string
 */
export const decrypt = async (key: Uint8Array, password: string, encrypted: EncryptedData): Promise<string> => {
	const { data, iv, salt, algorithm } = encrypted

	if (algorithm !== EncryptionAlgorithm.AES256GCM) {
		throw new Error("unsupported encryption algorithm")
	}

	if (algorithm === EncryptionAlgorithm.AES256GCM && key.length !== 32) {
		throw new Error("invalid key length for AES256-GCM")
	}

	const k = await deriveAESKey(key, password, decodeBase64(salt))
	const res = new Uint8Array(
		await window.crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: decodeBase64(iv), additionalData: new Uint8Array() },
			k,
			decodeBase64(data),
		),
	)

	return fromBytes(res)
}

/**
 * Generates a new encryption key based on a random encryption key and an optional password
 * @param key Random encryption key
 * @param password Optional password
 * @param salt Random salt
 * @returns AES crypto key
 */
const deriveAESKey = async (key: Uint8Array, password: string, salt: Uint8Array): Promise<CryptoKey> => {
	const iterations = 100000

	// If password is set, append it to the key
	const pwData = toBytes(password)
	if (pwData.length > 0) {
		const newKeyArray = new Uint8Array(key.length + password.length)
		newKeyArray.set(key, 0)
		newKeyArray.set(pwData, key.length)
		key = newKeyArray
	}

	// Import raw key
	const importedKey = await window.crypto.subtle.importKey(
		"raw", // Only 'raw' is allowed
		key, // Encryption key
		{ name: "PBKDF2" }, // Use PBKDF2 for key derivation
		false, // The key may not be exported
		["deriveKey"], // We may only use it for key derivation
	)

	// derive a stronger key for use with AES
	return window.crypto.subtle.deriveKey(
		{ name: "PBKDF2", salt, iterations, hash: { name: "SHA-256" } }, // Key algorithm
		importedKey,
		{ name: "AES-GCM", length: 256 }, // Set what the key is intended to be used for
		true, // The key may be exported
		["encrypt", "decrypt"], // We may only use it for en- and decryption
	)
}
