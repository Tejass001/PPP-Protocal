import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import unittest
from protocol.secure_channel import SecureChannel

class TestSecureChannel(unittest.TestCase):
    def setUp(self):
        self.alice = SecureChannel()
        self.bob = SecureChannel()

        # Exchange public keys
        self.alice_pub = self.alice.generate_public_key()
        self.bob_pub = self.bob.generate_public_key()

        # Derive shared keys
        self.alice.derive_keys(self.bob_pub)
        self.bob.derive_keys(self.alice_pub)

    def test_normal_encryption_decryption(self):
        message = b"Confidential message from Alice"
        nonce, ciphertext, tag = self.alice.encrypt_and_authenticate(message)
        decrypted = self.bob.decrypt_and_verify(nonce, ciphertext, tag)
        self.assertEqual(message, decrypted)

    def test_tampered_ciphertext(self):
        message = b"Message for integrity check"
        nonce, ciphertext, tag = self.alice.encrypt_and_authenticate(message)
        
        # Modify ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # flip some bits
        tampered = bytes(tampered)

        with self.assertRaises(ValueError):
            self.bob.decrypt_and_verify(nonce, tampered, tag)

    def test_invalid_tag(self):
        message = b"Test for tag mismatch"
        nonce, ciphertext, tag = self.alice.encrypt_and_authenticate(message)
        
        # Modify tag
        fake_tag = bytearray(tag)
        fake_tag[0] ^= 0xAA
        fake_tag = bytes(fake_tag)

        with self.assertRaises(ValueError):
            self.bob.decrypt_and_verify(nonce, ciphertext, fake_tag)

    def test_replay_attack_simulation(self):
        # Alice sends a message
        message = b"Replay attack test"
        nonce, ciphertext, tag = self.alice.encrypt_and_authenticate(message)

        # Bob receives it once (OK)
        result = self.bob.decrypt_and_verify(nonce, ciphertext, tag)
        self.assertEqual(message, result)

        # Replay the exact same packet (simulate MITM)
        # In a real system, we'd track used nonces/tags — this test just warns that replay goes undetected
        result2 = self.bob.decrypt_and_verify(nonce, ciphertext, tag)
        self.assertEqual(message, result2)  # Should pass but signal weakness without nonce tracking

if __name__ == "__main__":
    unittest.main()
