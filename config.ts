/**
 * Configuration settings for key derivation algorithms.
 */
export const config = {
	/** Key derivation settings for PBKDF2 */
	PBKDF2: {
		/** Length of the salt in bytes */
		saltLength: 16,

		/** Number of iterations for key derivation */
		iterations: 210000,

		/** Hash function used for key derivation */
		hash: "SHA-512" as "SHA-256" | "SHA-384" | "SHA-512",
	},

	/** Key derivation settings for Scrypt */
	Scrypt: {
		/** Length of the salt in bytes */
		saltLength: 16,

		/** Cost factor */
		N: 2 ** 15,

		/** Block size */
		r: 8,

		// Parallelization factor */
		p: 3,
	},
}
