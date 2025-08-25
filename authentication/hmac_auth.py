# authentication/hmac_auth.py
import hmac
import hashlib

class HMACAuth:
    def __init__(self, key: bytes):
        self.key = key

    def generate_hmac(self, data: bytes) -> bytes:
        # Return RAW BYTES (32 bytes for SHA-256), not hex text
        return hmac.new(self.key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, tag: bytes) -> bool:
        return hmac.compare_digest(self.generate_hmac(data), tag)

""" Example usage
if __name__ == "__main__":
    key = b'supersecretkey1234567890abcd!'  # 32 bytes for example
    message = b"Important message payload"

    auth = HMACAuth(key)
    tag = auth.generate_hmac(message)

    print("HMAC tag:", tag.hex())
    print("Is valid?", auth.verify_hmac(message, tag))
    print("Tampered?", auth.verify_hmac(message + b"!!!", tag))  # Should return False
"""
