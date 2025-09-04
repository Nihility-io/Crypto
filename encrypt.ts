import { xchacha20poly1305 } from "@noble/ciphers/chacha.js"
import {
	deriveKey,
	EncryptionAlgorithm,
	EncryptionError,
	KeyAlgorithm,
	randomBytes,
	toBytes,
	UnsupportedEncryptionAlgorithmError,
} from "./mod.ts"
import { CryptoURL } from "./parameters.ts"

/**
 * Encrypts the message using the given key and password
 * @param passphrase Passphrase used to encrypt the data
 * @param message Message to encrypt
 * @param algorithm Encryption algorithm (default: AES256-GCM)
 * @returns Encrypted data
 */
export function encrypt(
	passphrase: string | Uint8Array,
	message: string,
	algorithm?: EncryptionAlgorithm,
): Promise<string>

/**
 * Encrypts the message using the given key and password
 * @param passphrase Passphrase used to encrypt the data
 * @param message Message to encrypt
 * @param algorithm Encryption algorithm (default: AES256-GCM)
 * @returns Encrypted data
 */
export function encrypt(
	passphrase: string | Uint8Array,
	message: Uint8Array,
	algorithm?: EncryptionAlgorithm,
): Promise<[string, Uint8Array]>

/**
 * Encrypts the message using the given key and password
 * @param passphrase Passphrase used to encrypt the data
 * @param message Message to encrypt
 * @param algorithm Encryption algorithm (default: AES256-GCM)
 * @returns Encrypted data
 */
export async function encrypt(
	passphrase: string | Uint8Array,
	message: string | Uint8Array,
	algorithm = EncryptionAlgorithm.AES256GCM,
): Promise<unknown> {
	const data = typeof message === "string" ? toBytes(message) : message

	let res: CryptoURL

	switch (algorithm) {
		case EncryptionAlgorithm.AES256GCM:
			res = await encryptAES256GCM(passphrase, data)
			break
		case EncryptionAlgorithm.XChaCha20Poly1305:
			res = await encryptXChaCha20Poly1305(passphrase, data)
			break
		default:
			throw new UnsupportedEncryptionAlgorithmError(algorithm)
	}

	if (typeof message === "string") {
		return res.toString()
	}
	const dat = res.data
	res.data = new Uint8Array(0)
	return [res.toString(), dat]
}

/**
 * Encrypts the data with the given key and optional password using AES256-GCM
 * @param passphrase Passphrase used to encrypt the data
 * @param data Data to encrypt
 * @returns Encrypted data
 */
async function encryptAES256GCM(passphrase: string | Uint8Array, data: Uint8Array): Promise<CryptoURL> {
	const cryptoURL = new CryptoURL(EncryptionAlgorithm.AES256GCM, KeyAlgorithm.PBKDF2)
	const iv = cryptoURL.setBase58("nonce", randomBytes(12))
	const k = await deriveKey(passphrase, cryptoURL)

	try {
		const gcmParams = { name: "AES-GCM", iv: iv, additionalData: new Uint8Array() } satisfies AesGcmParams
		cryptoURL.data = new Uint8Array(await globalThis.crypto.subtle.encrypt(gcmParams, k as CryptoKey, data))
		return cryptoURL
	} catch (error) {
		throw new EncryptionError(error instanceof Error ? error.message : String(error))
	}
}

/**
 * Encrypts the data with the given key and optional password using XChaCha20-Poly1305
 * @param passphrase Passphrase used to encrypt the data
 * @param data Data to encrypt
 * @returns Encrypted data
 */
async function encryptXChaCha20Poly1305(passphrase: string | Uint8Array, data: Uint8Array): Promise<CryptoURL> {
	const cryptoURL = new CryptoURL(EncryptionAlgorithm.XChaCha20Poly1305, KeyAlgorithm.Scrypt)
	const nonce = cryptoURL.setBase58("nonce", randomBytes(xchacha20poly1305.nonceLength))
	const k = await deriveKey(passphrase, cryptoURL)

	try {
		cryptoURL.data = xchacha20poly1305(k as Uint8Array, nonce).encrypt(data)
		return cryptoURL
	} catch (error) {
		throw new EncryptionError(error instanceof Error ? error.message : String(error))
	}
}
