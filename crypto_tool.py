# Install cryptography library first: pip install cryptography
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class AESCipher:
    def __init__(self, key: bytes):
        # AES-256 requires a 32-byte key
        self.key = key

    def encrypt(self, plaintext: str) -> bytes:
        # Generate a random 16-byte Initialization Vector (IV)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Apply PKCS7 padding to make data block size compliant
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Prepend IV for use during decryption

    def decrypt(self, ciphertext_with_iv: bytes) -> str:
        iv = ciphertext_with_iv[:16]
        actual_ciphertext = ciphertext_with_iv[16:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()

# local testing execution
if __name__ == "__main__":
    # Generate a secure 32-byte key
    secret_key = os.urandom(32)
    cipher_system = AESCipher(secret_key)
    
    secret_message = "Confidential Data: Japanese University Admission Token 2026"
    print(f"Original Text: {secret_message}")
    
    encrypted_data = cipher_system.encrypt(secret_message)
    print(f"Encrypted Output (Hex): {encrypted_data.hex()[:50]}...")
    
    decrypted_data = cipher_system.decrypt(encrypted_data)
    print(f"Decrypted Output: {decrypted_data}")
