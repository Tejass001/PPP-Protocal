from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class ECDHKeyExchange:
    def __init__(self):
        #  ECDH private key
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def get_serialized_public_key(self):
        #  public key in PEM format
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_peer_public_key(self, peer_public_key_bytes):
        # Convert pp key (in bytes) into ECPublicKey object
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        return peer_public_key

    def generate_shared_secret(self, peer_public_key):
        # we get the shared secret using the private key and the peer's public key
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret
