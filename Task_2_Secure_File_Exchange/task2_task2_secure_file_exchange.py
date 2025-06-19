from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib

# Step 1: Generate RSA key pair for Bob
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("private.pem", "wb") as f:
    f.write(private_key)
with open("public.pem", "wb") as f:
    f.write(public_key)

# Step 2: Create Alice's message
message = b"This is a confidential message from Alice to Bob."
with open("alice_message.txt", "wb") as f:
    f.write(message)

# Step 3: Generate AES key and IV
aes_key = get_random_bytes(32)
iv = get_random_bytes(16)

# Step 4: Encrypt message using AES-256-CBC
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
padded = message + b"\0" * (16 - len(message) % 16)
ciphertext = cipher.encrypt(padded)

with open("encrypted_file.bin", "wb") as f:
    f.write(iv + ciphertext)

# Step 5: Encrypt AES key with RSA
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_key = cipher_rsa.encrypt(aes_key)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_key)

# Step 6: Bob decrypts AES key
cipher_rsa_dec = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_key = cipher_rsa_dec.decrypt(encrypted_key)

# Step 7: Bob decrypts message
with open("encrypted_file.bin", "rb") as f:
    enc_data = f.read()
iv_dec = enc_data[:16]
ciphertext_dec = enc_data[16:]

cipher_dec = AES.new(decrypted_key, AES.MODE_CBC, iv_dec)
decrypted_msg = cipher_dec.decrypt(ciphertext_dec).rstrip(b"\0")

with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_msg)

# Step 8: Integrity check
orig_hash = hashlib.sha256(message).hexdigest()
recv_hash = hashlib.sha256(decrypted_msg).hexdigest()

print("Integrity check:", "PASS" if orig_hash == recv_hash else "FAIL")