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





'''from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class ECDHKeyExchange:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def get_serialized_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_peer_public_key(self, peer_public_bytes):
        return serialization.load_pem_public_key(peer_public_bytes, backend=default_backend())

    def generate_shared_secret(self, peer_public_key):
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret

 testing (remove later)
if __name__ == "__main__":
    # Create Alice's ECDH instance and get her public key
    alice = ECDHKeyExchange()
    alice_pub_bytes = alice.get_serialized_public_key()

    # Create Bob's ECDH instance and get his public key
    bob = ECDHKeyExchange()
    bob_pub_bytes = bob.get_serialized_public_key()

    # Alice loads Bob's public key
    bob_pub_loaded = alice.load_peer_public_key(bob_pub_bytes)
    # Bob loads Alice's public key
    alice_pub_loaded = bob.load_peer_public_key(alice_pub_bytes)

    # Both derive shared secrets using the other's public key
    alice_secret = alice.generate_shared_secret(bob_pub_loaded)
    bob_secret = bob.generate_shared_secret(alice_pub_loaded)

    print("Shared secrets match:", alice_secret == bob_secret)
'''
