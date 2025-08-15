import { randomInt } from "@nihility-io/crypto"

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
	const characterSets = [
		options.useUppercase ? ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"] : [],
		options.useLowercase ? ["abcdefghijklmnopqrstuvwxyz"] : [],
		options.useDigits ? ["0123456789"] : [],
		options.useSymbols ? ["~!@#%&*_-+=,.?<>"] : [],
	].flat()

	if (characterSets.length > options.length) {
		throw new Error(`Password length must be at least ${characterSets.length}.`)
	}

	const passwordChars: string[] = []

	// Step 1: Ensure one char from each set
	for (const set of characterSets) {
		passwordChars.push(set[randomInt(set.length)])
	}

	// Step 2: Fill remaining chars from all sets combined
	const allChars = characterSets.join("")
	while (passwordChars.length < options.length) {
		passwordChars.push(allChars[randomInt(allChars.length)])
	}

	// Step 3: Shuffle securely
	for (let i = passwordChars.length - 1; i > 0; i--) {
		const j = randomInt(i + 1)
		;[passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]]
	}

	return passwordChars.join("")
}
