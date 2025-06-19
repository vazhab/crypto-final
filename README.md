# crypto-final
# Applied Cryptography – Final Exam (Submission)

This repository contains all deliverables for the Applied Cryptography final exam.

**Student:** Vazha Bichiashvili
**Date:** 19.06.2025
**Repository** https://github.com/vazhab/crypto-final

---

## Task Overview

### ✅ Task 1: Encrypted Messaging App Prototype (8 pts)

Implements a simple messaging system using:
- AES-256 encryption for messages
- RSA encryption for secure key exchange

**Deliverables:**
- `task1_messaging.py`
- `message.txt`
- `encrypted_message.bin`
- `aes_key_encrypted.bin`
- `decrypted_message.txt`
- `user_a_public.pem`, `user_a_private.pem`
- `README.md` (task-specific)

---

### ✅ Task 2: Secure File Exchange Using RSA + AES (8 pts)

Simulates hybrid encryption for file transmission:
- AES-256 for file encryption
- RSA for key protection
- SHA-256 for integrity verification

**Deliverables:**
- `task2_secure_file_exchange.py`
- `alice_message.txt`
- `encrypted_file.bin`
- `aes_key_encrypted.bin`
- `decrypted_message.txt`
- `public.pem`, `private.pem`
- `README.md` (task-specific)

---

### ✅ Task 3: TLS Communication Inspection & Analysis (8 pts)

Analyzes a TLS handshake and certificate chain using:
- `openssl s_client`
- Wireshark

**Deliverables:**
- `tls_summary.txt`
- `openssl_output.png` (screenshot)
- `wireshark_tls_handshake.png` (screenshot)

> ⚠️ Screenshots must be manually captured.

---

### ✅ Task 4: Email Encryption and Signature Simulation (8 pts)

Uses GPG to:
- Generate PGP keys for Alice and Bob
- Sign and encrypt a message from Alice
- Verify and decrypt it as Bob

**Deliverables:**
- `original_message.txt`
- `signed_message.asc`
- `decrypted_message.txt`
- `public.asc`, `private.key`
- `signature_verification.txt`

---

### ✅ Task 5: Hashing & Integrity Check Utility (8 pts)

Implements a Python utility to:
- Compute SHA-256, SHA-1, MD5
- Detect tampering by comparing hashes

**Deliverables:**
- `hash_util.py`
- `original.txt`, `tampered.txt`
- `hashes.json`

---

## How to Run

Ensure Python 3 and required libraries are installed:

```bash
pip install pycryptodome
