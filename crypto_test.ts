import { assertEquals } from "@std/assert"
import { decrypt, encrypt, EncryptionAlgorithm, randomBytes } from "./mod.ts"

Deno.test("Encryption/Decryption", async (t) => {
	const key = randomBytes(32)
	const pass = "abc123"
	const message = "Hello World!"

	await t.step("Password", async () => {
		const enc = await encrypt(key, pass, message, EncryptionAlgorithm.AES256GCM)
		const dec = await decrypt(key, pass, enc)
		assertEquals(dec, message)
	})

	await t.step("No Password", async () => {
		const enc = await encrypt(key, "", message, EncryptionAlgorithm.AES256GCM)
		const dec = await decrypt(key, "", enc)
		assertEquals(dec, message)
	})
})
