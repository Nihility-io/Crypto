import { assertEquals } from "@std/assert"
import { decrypt, encrypt, EncryptionAlgorithm, fromBytes, randomBytes } from "./mod.ts"

Deno.test("Encryption and Decryption", async (t) => {
	const randomKey = fromBytes(randomBytes(32))
	const password = "abc123"
	const message = "Hello World!"

	await t.step("AES256-GCM", async (t) => {
		await t.step("Random Key", async () => {
			const enc = await encrypt(randomKey, message, EncryptionAlgorithm.AES256GCM)
			const dec = await decrypt(randomKey, enc)
			assertEquals(dec, message)
		})

		await t.step("Password", async () => {
			const enc = await encrypt(password, message, EncryptionAlgorithm.AES256GCM)
			const dec = await decrypt(password, enc)
			assertEquals(dec, message)
		})
	})

	await t.step("XChaCha20Poly1305", async (t) => {
		await t.step("Random Key", async () => {
			const enc = await encrypt(randomKey, message, EncryptionAlgorithm.XChaCha20Poly1305)
			const dec = await decrypt(randomKey, enc)
			assertEquals(dec, message)
		})

		await t.step("Password", async () => {
			const enc = await encrypt(password, message, EncryptionAlgorithm.XChaCha20Poly1305)
			const dec = await decrypt(password, enc)
			assertEquals(dec, message)
		})
	})
})
