# Crypto
Collection of high level crypto functions

## Basic Usage
``` ts
import { decrypt, encrypt, EncryptionAlgorithm, randomBytes } from "jsr:@nihility-io/crypto"

const key = randomBytes(32)
const pass = "abc123"
const message = "Hello World!"

const enc = await encrypt(key, pass, message, EncryptionAlgorithm.AES256GCM)
const dec = await decrypt(key, pass, enc)
```