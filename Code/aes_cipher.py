import os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(32) # AES-256

    def encrypt(self, plaintext: str) -> dict:
        data_bytes = plaintext.encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data_bytes) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return {
            "key": base64.b64encode(self.key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    def decrypt(self, ciphertext_b64: str, iv_b64: str) -> str:
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
        return data.decode('utf-8')