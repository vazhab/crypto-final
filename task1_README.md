# Task 1: Encrypted Messaging App Prototype

## Encryption Flow

1. **User A** generates an RSA key pair (private and public keys).
2. **User B** prepares a secret message.
3. The message is encrypted with a randomly generated AES-256 key.
4. The AES key is then encrypted with User A's RSA public key.
5. User A receives:
   - `encrypted_message.bin`: the AES-encrypted message
   - `aes_key_encrypted.bin`: the RSA-encrypted AES key
6. User A decrypts the AES key with their RSA private key.
7. Then, User A decrypts the message using the decrypted AES key.

## Files

- `message.txt`: Original message
- `encrypted_message.bin`: AES-encrypted message
- `aes_key_encrypted.bin`: RSA-encrypted AES key
- `decrypted_message.txt`: Final decrypted message
- `user_a_private.pem`, `user_a_public.pem`: RSA key pair