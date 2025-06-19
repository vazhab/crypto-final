from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# Step 1: Generate RSA key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("user_a_private.pem", "wb") as f:
    f.write(private_key)
with open("user_a_public.pem", "wb") as f:
    f.write(public_key)

# Step 2: Create message and encrypt using AES
message = b"Hello User A, this is a top secret message!"
with open("message.txt", "wb") as f:
    f.write(message)

aes_key = get_random_bytes(32)
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

with open("encrypted_message.bin", "wb") as f:
    f.write(cipher_aes.nonce + tag + ciphertext)

# Step 3: Encrypt AES key with RSA public key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# Step 4: Decrypt AES key and then decrypt message
cipher_rsa_dec = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_aes_key = cipher_rsa_dec.decrypt(encrypted_aes_key)

with open("encrypted_message.bin", "rb") as f:
    data = f.read()
nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce)
decrypted_message = cipher_aes_dec.decrypt_and_verify(ciphertext, tag)

with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_message)