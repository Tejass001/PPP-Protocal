# protocol/secure_channel.py
import os, hashlib
from cryptography.hazmat.primitives import serialization
from key_exchange.ecdh_key_exchange import ECDHKeyExchange
from encryption.chacha20_encryption import ChaCha20Encryption
from authentication.hmac_auth import HMACAuth

class SecureChannel:

    def __init__(self):
        self.ecdh = ECDHKeyExchange()
        self._enc_key = None
        self._auth_key = None

    #  Key exchange
    def get_public_key_pem(self) -> bytes:

        return self.ecdh.get_serialized_public_key()

    def set_peer_public_key_pem(self, peer_pem: bytes):

        peer_public_key = serialization.load_pem_public_key(peer_pem)
        shared = self.ecdh.generate_shared_secret(peer_public_key)
        self._derive_symmetric_keys(shared)

    def _derive_symmetric_keys(self, shared_secret: bytes):
        # Simple KDF: SHA-512(shared)-> 64 bytes
        full = hashlib.sha512(shared_secret).digest()
        self._enc_key  = full[:32]
        self._auth_key = full[32:64]

    def ready(self) -> bool:
        return self._enc_key is not None and self._auth_key is not None

    #  Data plane
    def encrypt_and_authenticate(self, plaintext: bytes) -> bytes:

        if not self.ready():
            raise RuntimeError("SecureChannel is not ready (keys not derived).")
        nonce = os.urandom(16)
        chacha = ChaCha20Encryption(self._enc_key, nonce)
        ct = chacha.encrypt(plaintext)
        tag = HMACAuth(self._auth_key).generate_hmac(nonce + ct)
        return nonce + ct + tag

    def decrypt_and_verify(self, payload: bytes) -> bytes | None:

        if not self.ready():
            raise RuntimeError("SecureChannel is not ready (keys not derived).")
        if len(payload) < 16 + 32:
            return None
        nonce = payload[:16]
        tag   = payload[-32:]
        ct    = payload[16:-32]
        if not HMACAuth(self._auth_key).verify_hmac(nonce + ct, tag):
            return None
        return ChaCha20Encryption(self._enc_key, nonce).decrypt(ct)

