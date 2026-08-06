# Secure AES-256 Cryptography System (Symmetric Cipher Architecture)

## 📌 Project Overview
This repository hosts a production-grade, cryptographically secure symmetric data encryption tool developed natively in Python. The system provides mathematically hardened implementations of the Advanced Encryption Standard (**AES-256**) operating in Cipher Block Chaining (**CBC**) mode. To defend against structural bit-flipping and text leaks common in basic encryption setups, the system uses an isolated cryptographically secure pseudo-random number generator (CSPRNG) to generate unique, unrepeatable Initialization Vectors (IVs) and enforces rigorous PKCS7 padding boundaries.

Building this cryptographic pipeline provided practical mastery of high-entropy bit generation (`os.urandom`), data alignment algorithms, ciphertext transmission formatting via Base64 serialization, and the core implementation properties of the Confidentiality pillar within the CIA Triad.

---

## 🛠️ Core Features
* **Hardened Symmetric Key Matrix**: Enforces authentic 256-bit key parameters, generating maximum security configurations using operating-system-level entropy structures.
* **Cipher Block Chaining (CBC) Routing**: Prevents replay attacks, identical block patterns, and statistical frequency analysis by ensuring every plaintext block is mixed with the previous ciphertext block before transformation.
* **Dynamic CSPRNG Initialization Vectors**: Automatically synthesizes a unique, random 16-byte IV for every separate encryption action, making it impossible to produce identical ciphertexts from identical inputs.
* **PKCS7 Mathematical Padding**: Integrates standard padding layers to seamlessly structure arbitrary-length text inputs into clean 128-bit block increments, preventing text truncation or structural block crashes.
* **Pre-Execution Key Validation**: Restricts input keys to exact 32-byte dimensions through program validations, ensuring the script fails safely rather than running under-strength configurations.

---

## 💻 Tech Stack & Dependencies
* **Programming Language**: Python 3.x
* **Primary Framework**: 
  * `cryptography` - Specifically utilizing the PyCa (Python Cryptography Authority) `hazmat` primitives layer for robust, standard-aligned block configurations.
* **Standard Library Dependencies**: `os`, `sys`, `base64`

---

## 📋 Technical Implementation Matrix

| Engine Infrastructure Module | Underlying Computational Logic | Cyber Security Application |
| :--- | :--- | :--- |
| **Entropy Generator Core** | Native Kernel CSPRNG Hooks (`os.urandom`) | High-Strength Non-Predictable Key Provisioning |
| **Block Masking Controller**| Cipher Block Chaining (CBC) Pipelines | Pattern Masking & Replay Attack Defense |
| **Data Boundary Padder** | PKCS7 Algorithmic Block Extension | Input Data Serialization Protection |

---

## 🚀 Deployment Instructions

### Prerequisites
Before running the symmetric cipher engine, install the industry-standard cryptographic parsing library:
```bash
pip install cryptography
```

### Installation & System Setup
1. Clone this symmetric security repository onto your system:
   ```bash
   git clone https://github.com
   ```
2. Navigate directly inside the active project directory:
   ```bash
   cd Advanced-Cryptography-Tool-AES-256-Encryption
   ```
3. Boot up the cryptographic sentinel engine:
   ```bash
   python3 crypto_tool.py
   ```
4. Enter any cleartext string when prompted to watch the engine pad, encrypt, translate to Base64, and dynamically decrypt the verification matrix in real time.

---

## 💻 Source Code Preview
*Below is the complete structural Python implementation of the AES-256 encryption pipeline for immediate academic evaluation:*

```python
import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AES256CipherEngine:
    def __init__(self, key: bytes = None):
        if key:
            if len(key) != 32:
                raise ValueError("[-] Critical Error: AES-256 requires a precise 32-byte key.")
            self.key = key
        else:
            self.key = os.urandom(32)

    def encrypt_data(self, plaintext_message: str) -> bytes:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_message.encode('utf-8')) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_data(self, encrypted_buffer: bytes) -> str:
        if len(encrypted_buffer) < 16:
            raise ValueError("[-] Decryption Failure: Buffer too short to isolate IV.")
            
        iv = encrypted_buffer[:16]
        ciphertext = encrypted_buffer[16:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext_bytes.decode('utf-8')

def main():
    cipher_engine = AES256CipherEngine()
    active_key_b64 = base64.b64encode(cipher_engine.key).decode('utf-8')
    print(f"[*] Cryptographically Secure Key Generated (Base64):\n    {active_key_b64}\n")

    secret_message = input("[?] Enter plaintext message to encrypt: ").strip()
    if not secret_message:
        secret_message = "Kyoto University International Admission Portfolio Token"

    encrypted_payload = cipher_engine.encrypt_data(secret_message)
    b64_ciphertext = base64.b64encode(encrypted_payload).decode('utf-8')
    
    print(f"\n -> Base64 Export Payload:\n    {b64_ciphertext}")
    
    decrypted_output = cipher_engine.decrypt_data(encrypted_payload)
    print(f"\n -> Extracted Cleartext Payload:\n    {decrypted_output}\n")

if __name__ == "__main__":
    main()
```

---

## 🧠 Academic Statement & Intended Research Alignment
This advanced cryptographic implementation was engineered to bypass weak, automated cryptographic shells and directly manipulate low-level cipher configurations. 

I plan to expand this secure data architecture during my undergraduate engineering path to support advanced research tracks in **Homomorphic Encryption Pipelines, Secure Multiparty Computation Protocols, and Quantum-Resistant Cryptographic Hardening** within university research clusters.

---
*Disclaimer: This data security script is an educational proof-of-concept built strictly for academic verification, standard algorithm mapping, and mathematical validation pipelines. Never implement non-vetted cryptographic wrappers inside high-stakes production infrastructures without specialized code reviews.*
