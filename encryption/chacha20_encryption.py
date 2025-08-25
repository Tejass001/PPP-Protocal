from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os

class ChaCha20Encryption:
    def __init__(self, key: bytes, nonce: bytes):
        if len(key) != 32 or len(nonce) != 16:
            raise ValueError("Key must be 32 bytes and nonce must be 16 bytes for ChaCha20")
        self.key = key
        self.nonce = nonce

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = Cipher(algorithms.ChaCha20(self.key, self.nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.ChaCha20(self.key, self.nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext)
        return plaintext
""" testing (remove later)
if __name__ == "__main__":
    key = os.urandom(32)
    nonce = os.urandom(16)
    message = b"Confidential message for transmission."

    crypto = ChaCha20Encryption(key, nonce)
    encrypted = crypto.encrypt(message)
    decrypted = crypto.decrypt(encrypted)

    print("Original :", message)
    print("Encrypted:", encrypted.hex())
    print("Decrypted:", decrypted)

"""
