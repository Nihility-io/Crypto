export * from "./config.ts"
export * from "./decrypt.ts"
export * from "./encrypt.ts"
export * from "./errors.ts"
export * from "./keys.ts"
export * from "./parameters.ts"
export * from "./password.ts"

/**
 * Generates a random Uint8Array with a given length
 * @param length Number of bytes to return
 * @returns A Uint8Array with random bytes
 */
export function randomBytes(length: number): Uint8Array {
	return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

/**
 * Converts a raw string into a bytes
 * @param s String
 * @returns Bytes
 */
export function toBytes(s: string): Uint8Array {
	return new TextEncoder().encode(s)
}

/**
 * Converts bytes into a raw string
 * @param b Bytes
 * @returns String
 */
export function fromBytes(b: Uint8Array): string {
	return new TextDecoder().decode(b)
}

/**
 * Generates a random integer in the range [0, max)
 * @param max Maximum value (exclusive)
 * @returns Random integer
 */
export function randomInt(max: number): number {
	return crypto.getRandomValues(new Uint32Array(1))[0] % max
}
