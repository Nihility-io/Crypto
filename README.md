# Crypto
Nihility.io Crypto is a collection of high level cryptographic functions. This package is mainly intended for my project SecretBin but you may also use it if you find it useful.

## Encryption and Decryption
Nihility.io Crypto provides high level functions for encrypting and decrypting string messages. When encrypting a string using `encrypt`, it returns a string which looks like an URL. This string contains all the information necessary to decrypt the data again. Said string is called a CryptoURL and has the following format:
 - **crypto://?algorithm=<encryption_algorithm>&key-algorithm=<key_algorithm>&<additional_parameters...>#<encrypted_message>**
In order to decrypt the CryptoURL, use `decrypt` with the passphrase used to encrypt the message.

### Supported Algorithms
- AES256-GCM with PBKDF2: This method relies on Web Crypto in the browser for encryption and key derivation.
- XChaCha20-Poly1305 with Scrypt: This method relies on the @noble/ciphers library, which implements encryption and key derivation using JavaScript.

### Usage
``` ts
import { decrypt, encrypt, EncryptionAlgorithm, config } from "@jsr:@nihility-io/crypto"

// You may configure the encryption parameters if you want. These are the defaults:
config.PBKDF2.saltLength = 16
config.PBKDF2.iterations = 210000
config.PBKDF2.hash = "SHA-512"
config.Scrypt.saltLength = 16
config.Scrypt.N = 2 ** 15
config.Scrypt.r = 8
config.Scrypt.p = 3

const passphrase = "my super secure password"
const message = "Hello, world!"

{ // Encryption using AES256-GCM
	const encrypted = await encrypt(passphrase, message, EncryptionAlgorithm.AES256GCM)
	console.log(encrypted) // => crypto://?algorithm=AES256-GCM&key-algorithm=pbkdf2&nonce=4iq93GBn5cC3VScS2&salt=dvUBWwmV8kU&iter=100000&hash=SHA-256#w0WVtAMHRETJ1xjpZ1ISs99NCu4sk4f/X6+8TjY=
	const decrypted = await decrypt(passphrase, encrypted)
	console.log(decrypted) // => Hello, world!
}

{ // Encryption using XChaCha20-Poly1305
	const encrypted = await encrypt(passphrase, message, EncryptionAlgorithm.XChaCha20Poly1305)
	console.log(encrypted) // => crypto://?algorithm=XChaCha20Poly1305&key-algorithm=scrypt&nonce=5C1oK5Wn4JjeQgrth6cTak8RfXdXhLG1J&salt=cemv2C4Wx71&n=65536&r=1&p=8#sA8clh0eiBdXArj1788vKqnpQVm0FpE40qm9tyw=
	const decrypted = await decrypt(passphrase, encrypted)
	console.log(decrypted) // => Hello, world!
}
```

## Password Generation
Nihility.io Crypto provides cryptographically random password generator.

### Usage
``` ts
import { generatePassword } from "@jsr:@nihility-io/crypto"

const password = generatePassword({
	useUppercase: true,
	useLowercase: true,
	useDigits: true,
	useSymbols: true,
	length: 12,
})
console.log(password) // => &u7y6EHQCyNP
```