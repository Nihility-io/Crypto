import { decodeBase58, encodeBase58 } from "@std/encoding/base58"
import { decodeBase64, encodeBase64 } from "@std/encoding/base64"
import { InvalidCryptoParametersError, InvalidEncryptionParameterError, ReservedKeysError } from "./mod.ts"

export enum EncryptionAlgorithm {
	AES256GCM = "AES256-GCM",
	XChaCha20Poly1305 = "XChaCha20Poly1305",
}

/**
 * Checks if the given value is a valid encryption algorithm.
 * @param value Value to check
 * @returns True if value is a valid encryption algorithm, false otherwise
 */
function isEncryptionAlgorithm(value: string): value is EncryptionAlgorithm {
	return Object.values(EncryptionAlgorithm).includes(value as EncryptionAlgorithm)
}

export enum KeyAlgorithm {
	PBKDF2 = "pbkdf2",
	Scrypt = "scrypt",
}

/**
 * Checks if the given value is a valid key algorithm.
 * @param value Value to check
 * @returns True if value is a valid key algorithm, false otherwise
 */
function isKeyAlgorithm(value: string): value is KeyAlgorithm {
	return Object.values(KeyAlgorithm).includes(value as KeyAlgorithm)
}

export class CryptoURL {
	#params: Record<string, string>
	#data: Uint8Array

	/**
	 * Parse the encryption parameters from a crypto URL or create a new instance with the given algorithm and key algorithm.
	 * @param url Crypto URL to parse
	 */
	public constructor(url: string, data?: Uint8Array)

	/**
	 * Creates a new instance with the given encryption algorithm and key algorithm.
	 * @param algorithm Encryption algorithm to use
	 * @param keyAlgorithm Key algorithm to use
	 */
	public constructor(algorithm: EncryptionAlgorithm, keyAlgorithm: KeyAlgorithm)
	public constructor() {
		// Check if the constructor was called with two arguments (algorithm and keyAlgorithm)
		if (arguments.length === 2 && typeof arguments[1] === "string") {
			this.#data = new Uint8Array(0)
			this.#params = {}
			this.algorithm = arguments[0] as EncryptionAlgorithm
			this.keyAlgorithm = arguments[1] as KeyAlgorithm
			return
		}

		const url = arguments[0] as string
		const data = arguments[1] as Uint8Array | undefined

		const [rawParamURL, encodedData] = url.split("#")

		if (data) {
			this.#data = data
		} else {
			if (!rawParamURL || !encodedData) {
				throw new InvalidCryptoParametersError(url)
			}
			this.#data = decodeBase64(encodedData)
		}

		let paramURL: URL

		// Try to parse the URL, if it fails, throw an error
		try {
			paramURL = new URL(rawParamURL)
		} catch {
			throw new InvalidCryptoParametersError(url)
		}

		// Ensure the URL has the correct protocol
		if (paramURL.protocol !== "crypto:") {
			throw new InvalidCryptoParametersError(url)
		}

		this.#params = paramURL.searchParams.entries()
			.reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {})
		this.algorithm = this.#params["algorithm"] as EncryptionAlgorithm
		this.keyAlgorithm = this.#params["key-algorithm"] as KeyAlgorithm
	}

	/**
	 * Gets or sets the encrypted data.
	 */
	public get data(): Uint8Array {
		return this.#data
	}

	/**
	 * Gets or sets the encrypted data.
	 */
	public set data(value: Uint8Array) {
		this.#data = value
	}

	/**
	 * Gets or sets the encryption algorithm used for the encryption parameters.
	 */
	public get algorithm(): EncryptionAlgorithm {
		return this.#params["algorithm"] as EncryptionAlgorithm
	}

	/**
	 * Gets or sets the encryption algorithm used for the encryption parameters.
	 */
	public set algorithm(value: EncryptionAlgorithm) {
		if (!isEncryptionAlgorithm(value)) {
			throw new InvalidEncryptionParameterError("algorithm", value)
		}
		this.#params["algorithm"] = value
	}

	/**
	 * Gets or sets the key algorithm used for the encryption parameters.
	 */
	public get keyAlgorithm(): KeyAlgorithm {
		return this.#params["key-algorithm"] as KeyAlgorithm
	}

	/**
	 * Gets or sets the key algorithm used for the encryption parameters.
	 */
	public set keyAlgorithm(value: KeyAlgorithm) {
		if (!isKeyAlgorithm(value)) {
			throw new InvalidEncryptionParameterError("key-algorithm", value)
		}
		this.#params["key-algorithm"] = value
	}

	/**
	 * Gets the string representation of the crypto parameters in the format of a crypto URL.
	 * @returns Crypto URL
	 */
	public toString(): string {
		const urlParams = new URLSearchParams(this.#params)
		return new URL(`crypto://?${urlParams.toString()}`).toString() + "#" + encodeBase64(this.#data)
	}

	/**
	 * Asserts that the given key is not a reserved key.
	 * @param key Parameter key to check
	 */
	#assertReservedKeys(key: string): void {
		if (key === "algorithm" || key === "key-algorithm") {
			throw new ReservedKeysError()
		}
	}

	/**
	 * Gets the value for the given parameter key.
	 * - If the parameter is not set and no default value is provided, an error is thrown.
	 * - If the parameter is not set and a default value is provided, the default value is returned and set in the parameters.
	 * @param key Parameter key to get
	 * @param defaultValue Default value to return if the parameter is not set
	 * @returns Parameter value
	 */
	public get(key: string): string
	public get(key: string, defaultValue: string): string
	public get(key: string, defaultValue?: string): string {
		this.#assertReservedKeys(key)

		if (!this.#params[key]) {
			if (defaultValue === undefined) {
				throw new InvalidEncryptionParameterError(key, this.#params[key])
			}
			this.#params[key] = defaultValue
			return defaultValue
		}

		return this.#params[key]
	}

	/**
	 * Gets the value for the given parameter key.
	 * - If the parameter is not set and no default value is provided, an error is thrown.
	 * - If the parameter is not set and a default value is provided, the default value is returned and set in the parameters.
	 * @param key Parameter key to get
	 * @param defaultValue Default value to return if the parameter is not set
	 * @returns Parameter value
	 */
	public getNumber(key: string): number
	public getNumber(key: string, defaultValue: number): number
	public getNumber(key: string, defaultValue?: number): number {
		if (defaultValue === undefined) {
			return +this.get(key)
		}
		return +this.get(key, String(defaultValue))
	}

	/**
	 * Gets the value for the given parameter key and decodes it from Base58.
	 * - If the parameter is not set and no default value is provided, an error is thrown.
	 * - If the parameter is not set and a default value is provided, the default value is returned and set in the parameters.
	 * @param key Parameter key to get
	 * @param defaultValue Default value to return if the parameter is not set
	 * @returns Parameter value
	 */
	public getBase58(key: string): Uint8Array
	public getBase58(key: string, defaultValue: Uint8Array): Uint8Array
	public getBase58(key: string, defaultValue?: Uint8Array): Uint8Array {
		const value = defaultValue === undefined ? this.get(key) : this.get(key, encodeBase58(defaultValue))
		try {
			return decodeBase58(value)
		} catch {
			throw new InvalidEncryptionParameterError(key, this.#params[key])
		}
	}

	/**
	 * Gets the value for the given parameter key.
	 * @param key Parameter key to set
	 * @param value Parameter value to set
	 * @returns The value that was set
	 */
	public set(key: string, value: string): string {
		this.#assertReservedKeys(key)

		this.#params[key] = value
		return value
	}

	/**
	 * Gets the value for the given parameter key.
	 * @param key Parameter key to set
	 * @param value Parameter value to set
	 * @returns The value that was set
	 */
	public setNumber(key: string, value: number): number {
		this.set(key, String(value))
		return value
	}

	/**
	 * Gets the value for the given parameter key and encodes it to Base58.
	 * @param key Parameter key to set
	 * @param value Parameter value to set
	 * @returns The value that was set
	 */
	public setBase58(key: string, value: Uint8Array): Uint8Array {
		this.set(key, encodeBase58(value))
		return value
	}
}
