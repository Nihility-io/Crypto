import { randomBytes } from "./mod.ts"

export interface PasswordGeneratorOptions {
	useUppercase: boolean
	useLowercase: boolean
	useDigits: boolean
	useSymbols: boolean
	length: number
}

/**
 * Generates a random password at a given length using a given set of characters
 * @param options Specify the password length and characters
 * @returns Random password
 */
export function generatePassword(options: PasswordGeneratorOptions): string {
	const characters = [
		options.useUppercase ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "",
		options.useLowercase ? "abcdefghijklmnopqrstuvwxyz" : "",
		options.useDigits ? "0123456789" : "",
		options.useSymbols ? "~!@#%&*_-+=,.?<>" : "",
	].join("")
	return Array.from(randomBytes(options.length))
		.map((x) => characters[x % characters.length])
		.join("")
}
