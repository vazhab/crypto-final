# Task 2: Secure File Exchange Using RSA + AES

## Steps Followed

1. Generated RSA key pair for Bob.
2. Alice composed a secret message in `alice_message.txt`.
3. Alice encrypted the message using AES-256 in CBC mode.
4. The AES key was encrypted using Bob's RSA public key.
5. Bob decrypted the AES key using his RSA private key.
6. Bob decrypted the message using AES and verified the content.
7. SHA-256 hash check was used for integrity verification.

## Integrity Check: **PASS**

## Files

- `alice_message.txt`: Original message
- `encrypted_file.bin`: AES-encrypted file
- `aes_key_encrypted.bin`: RSA-encrypted AES key
- `decrypted_message.txt`: Decrypted message
- `public.pem`, `private.pem`: RSA key pair