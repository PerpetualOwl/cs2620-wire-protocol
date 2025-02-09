import unittest
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import json
import hashlib
from utils import (
    ClientPacket, ServerPacket, ChatMessage, ChatData, 
    MessageType, hash_password, generate_key_pair,
    encrypt, decrypt, serialize_packet, deserialize_packet
)

class TestSecureChat(unittest.TestCase):

    def setUp(self):
        # Generate key pair for encryption/decryption tests
        self.private_key, self.public_key = generate_key_pair()
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def test_hash_password(self):
        password = "securepassword"
        hashed = hash_password(password)
        self.assertEqual(hashlib.sha256(password.encode('utf-8')).hexdigest(), hashed)
        with self.assertRaises(ValueError):
            hash_password(123) # non-string input raises ValueError

    def test_generate_key_pair(self):
        private_pem, public_pem = generate_key_pair()
        self.assertIn(b'BEGIN PRIVATE KEY', private_pem)
        self.assertIn(b'BEGIN PUBLIC KEY', public_pem)

    def test_encrypt_decrypt(self):
        message = b"test message"
        ciphertext = encrypt(self.public_key, message)
        plaintext = decrypt(self.private_key, ciphertext)
        self.assertEqual(message, plaintext)

    def test_serialize_deserialize_packet(self):
        # Test ClientPacket serialization and deserialization        
        client_packet = ClientPacket(type=MessageType.CREATE_USER_REQUEST, data={"username": "testuser", "password": "testpass"})
        serialized_packet = serialize_packet(client_packet)
        deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
        self.assertEqual(client_packet, deserialized_packet)

        # Test ServerPacket serialization and deserialization
        server_packet = ServerPacket(type=MessageType.USER_ADDED, data={"username": "testuser"})
        serialized_packet = serialize_packet(server_packet)
        deserialized_packet = deserialize_packet(serialized_packet, ServerPacket)
        self.assertEqual(server_packet, deserialized_packet)

    def test_chat_message(self):
        msg = ChatMessage(sender="Alice", recipient="Bob", message="Hello!", message_id="123")
        self.assertEqual(msg.sender, "Alice")
        self.assertEqual(msg.recipient, "Bob")
        self.assertEqual(msg.message, "Hello!")
        
    def test_chat_data(self):
        chat_data = ChatData()
        chat_data.add_user("Alice")
        self.assertIn("Alice", chat_data.users)
        
        chat_data.add_user("Bob")
        message = ChatMessage(sender="Alice", recipient="Bob", message="Hi", message_id="1")
        chat_data.add_message(message)
        self.assertIn("1", chat_data.messages)

        chat_data.delete_message("Alice", "1")
        self.assertNotIn("1", chat_data.messages)

        chat_data.delete_user("Alice")
        self.assertNotIn("Alice", chat_data.users)

    def test_invalid_packet_serialization(self):
        with self.assertRaises(ValueError):
            # Should raise error on missing required fields
            ClientPacket(type=MessageType.SEND_MESSAGE, data={"sender": "Alice"})

if __name__ == "__main__":
    unittest.main()