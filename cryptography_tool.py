import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AES256EncryptionTool:
    """
    An enterprise-grade cryptographic utility implementing symmetric AES-256 encryption 
    in Cipher Block Chaining (CBC) mode with secure PKCS7 padding architectures.
    """
    def __init__(self, secret_key: str):
        # Enforce strict 32-byte (256-bit) key constraints using bitwise padding
        self.key = secret_key.encode('utf-8').ljust(32, b'\0')[:32]
        self.backend = default_backend()

    def encrypt_message(self, plaintext: str) -> str:
        """Encrypts symmetric blocks using a cryptographically secure pseudo-random IV."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Apply standard PKCS7 padding to align with strict 128-bit block sizes
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_message(self, ciphertext_b64: str) -> str:
        """Parses bitstream payloads, isolates the initialization vector, and restores plaintext data."""
        raw_data = base64.b64decode(ciphertext_b64.encode('utf-8'))
        iv = raw_data[:16]
        actual_ciphertext = raw_data[16:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        
        plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')

if __name__ == "__main__":
    print("=" * 65)
    print("   ADVANCED CRYPTOGRAPHIC ENGINE - AES-256 COMPLIANCE MATRIX   ")
    print("=" * 65)
    
    user_key = input("[?] Enter Private Symmetric Key: ").strip()
    tool = AES256EncryptionTool(user_key)
    
    secret_msg = input("[?] Enter Sensitive Plaintext String: ")
    encrypted = tool.encrypt_message(secret_msg)
    print(f"\n[+] Generated Ciphertext Output (Base64 Enveloped):\n{encrypted}")
    
    decrypted = tool.decrypt_message(encrypted)
    print(f"\n[+] Executing Decryption Protocol...")
    print(f"[SUCCESS] Restored Academic Plaintext: {decrypted}")
    print("=" * 65)
