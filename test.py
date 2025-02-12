import unittest
import json
import struct
import hashlib
from datetime import datetime
import os

# Import the module (and the global flag) so we can change it during tests.
import utils
from utils import (
    ClientPacket,
    ServerPacket,
    ChatMessage,
    ChatData,
    MessageType,
    hash_password,
    generate_key_pair,
    encrypt,
    decrypt,
    serialize_packet,
    deserialize_packet,
)

class TestSecureChat(unittest.TestCase):

    def setUp(self):
        # Generate a key pair (PEM bytes) for our encryption/decryption tests.
        self.private_key, self.public_key = generate_key_pair()
        # Make sure every test starts with the default protocol mode (JSON wire protocol)
        utils.USE_CUSTOM_WIRE_PROTOCOL = False

    def tearDown(self):
        # Restore default protocol mode after each test.
        utils.USE_CUSTOM_WIRE_PROTOCOL = False

    # --------------------
    # hash_password tests
    # --------------------
    def test_hash_password(self):
        password = "securepassword"
        hashed = hash_password(password)
        expected = hashlib.sha256(password.encode("utf-8")).hexdigest()
        self.assertEqual(expected, hashed)
        with self.assertRaises(ValueError):
            hash_password(123)  # non-string input should raise ValueError

    # ---------------------
    # generate_key_pair tests
    # ---------------------
    def test_generate_key_pair(self):
        private_pem, public_pem = generate_key_pair()
        self.assertIn(b"BEGIN PRIVATE KEY", private_pem)
        self.assertIn(b"BEGIN PUBLIC KEY", public_pem)

    # ---------------------
    # Encryption/Decryption tests
    # ---------------------
    def test_encrypt_decrypt(self):
        message = b"test message"
        ciphertext = encrypt(self.public_key, message)
        plaintext = decrypt(self.private_key, ciphertext)
        self.assertEqual(message, plaintext)

    def test_encrypt_invalid_public_key(self):
        # Passing invalid PEM bytes should cause an exception when trying to load the public key.
        with self.assertRaises(Exception):
            encrypt(b"not a valid PEM", b"message")

    def test_decrypt_invalid_data(self):
        # If the input data is not properly structured it should fail during decryption.
        with self.assertRaises(Exception):
            decrypt(self.private_key, b"random invalid data")

    # ---------------------
    # Packet serialization (JSON mode)
    # ---------------------
    def test_serialize_deserialize_packet_json(self):
        # Test for a ClientPacket in JSON mode.
        client_packet = ClientPacket(
            type=MessageType.CREATE_USER_REQUEST,
            data={"username": "testuser", "password": "testpass"},
        )
        serialized_packet = serialize_packet(client_packet)
        deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
        self.assertEqual(client_packet, deserialized_packet)

        # Test for a ServerPacket in JSON mode.
        server_packet = ServerPacket(
            type=MessageType.USER_ADDED,
            data={"username": "testuser"},
        )
        serialized_packet = serialize_packet(server_packet)
        deserialized_packet = deserialize_packet(serialized_packet, ServerPacket)
        self.assertEqual(server_packet, deserialized_packet)

    # ---------------------
    # Packet serialization (custom TLV wire protocol)
    # ---------------------
    def test_serialize_deserialize_packet_custom_wire_protocol(self):
        original_flag = utils.USE_CUSTOM_WIRE_PROTOCOL
        utils.USE_CUSTOM_WIRE_PROTOCOL = True
        try:
            # Test ClientPacket roundtrip.
            client_packet = ClientPacket(
                type=MessageType.CREATE_USER_REQUEST,
                data={"username": "customuser", "password": "custompass"},
            )
            serialized_packet = serialize_packet(client_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
            self.assertEqual(client_packet, deserialized_packet)

            # Test ServerPacket roundtrip.
            server_packet = ServerPacket(
                type=MessageType.PUBLIC_KEY_RESPONSE, data={"public_key": "some_key"}
            )
            serialized_packet = serialize_packet(server_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ServerPacket)
            self.assertEqual(server_packet, deserialized_packet)

            # If data is None, it should be encoded/decoded as an empty dictionary.
            client_packet = ClientPacket(
                type=MessageType.REQUEST_PUBLIC_KEY, data=None
            )
            serialized_packet = serialize_packet(client_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
            self.assertEqual(deserialized_packet.data, {})
        finally:
            utils.USE_CUSTOM_WIRE_PROTOCOL = original_flag

    def test_serialize_deserialize_packet_invalid_custom(self):
        # When using the custom TLV protocol and the first byte is an unknown packet code,
        # deserialization should raise a ValueError.
        original_flag = utils.USE_CUSTOM_WIRE_PROTOCOL
        utils.USE_CUSTOM_WIRE_PROTOCOL = True
        try:
            invalid_packet_bytes = struct.pack("!B", 255) + b"\x00"
            with self.assertRaises(ValueError):
                deserialize_packet(invalid_packet_bytes, ClientPacket)
        finally:
            utils.USE_CUSTOM_WIRE_PROTOCOL = original_flag

    # ---------------------
    # Model validator tests for Client and Server packets
    # ---------------------
    def test_client_packet_validator_missing_required_data(self):
        # For a SEND_MESSAGE packet, required fields like 'recipient', 'message', 'password' are missing.
        with self.assertRaises(ValueError):
            ClientPacket(
                type=MessageType.SEND_MESSAGE, data={"sender": "Alice"}
            )

    def test_server_packet_validator_missing_required_data(self):
        # For a USER_ADDED server packet, the 'username' field is required.
        with self.assertRaises(ValueError):
            ServerPacket(type=MessageType.USER_ADDED, data={})

    # ---------------------
    # ChatMessage tests
    # ---------------------
    def test_chat_message(self):
        msg = ChatMessage(
            sender="Alice", recipient="Bob", message="Hello!", message_id="123"
        )
        self.assertEqual(msg.sender, "Alice")
        self.assertEqual(msg.recipient, "Bob")
        self.assertEqual(msg.message, "Hello!")

        # Check that model_dump converts the datetime to an ISO‐formatted string.
        dumped = msg.model_dump()
        self.assertIsInstance(dumped["timestamp"], str)

        # If an invalid ISO datetime is provided in 'my_datetime', the validator should reject it.
        with self.assertRaises(ValueError):
            ChatMessage(
                sender="Alice",
                recipient="Bob",
                message="Hi",
                message_id="456",
                my_datetime="invalid-datetime",
            )

    def test_chat_message_datetime_parsing(self):
        # Provide a valid ISO datetime in 'my_datetime' (with trailing 'Z' time zone)
        iso_time = "2023-10-31T13:45:00Z"
        msg = ChatMessage(
            sender="Alice", recipient="Bob", message="Hello", message_id="789", my_datetime=iso_time
        )
        # Even though the field is named 'timestamp', the validator processing 'my_datetime'
        # should not cause any error and the resulting message has a valid datetime.
        self.assertIsInstance(msg.timestamp, datetime)

    # ---------------------
    # ChatData tests
    # ---------------------
    def test_chat_data(self):
        chat_data = ChatData()
        chat_data.add_user("Alice")
        self.assertIn("Alice", chat_data.users)

        chat_data.add_user("Bob")
        message = ChatMessage(
            sender="Alice", recipient="Bob", message="Hi", message_id="1"
        )
        chat_data.add_message(message)
        self.assertIn("1", chat_data.messages)

        # Automatically add users if they were not already added.
        message2 = ChatMessage(
            sender="Charlie", recipient="Dave", message="Hey", message_id="2"
        )
        chat_data.add_message(message2)
        self.assertIn("Charlie", chat_data.users)
        self.assertIn("Dave", chat_data.users)

        # Test that get_messages returns only messages associated with the provided username.
        filtered = chat_data.get_messages("Alice")
        self.assertIn("1", filtered.messages)
        self.assertNotIn("2", filtered.messages)
        
        # Backend will not let other users delete message.
        result = chat_data.delete_message("Bob", "1", True)
        self.assertFalse(result)

        # Valid deletion: deleting an existing message with the proper user.
        result = chat_data.delete_message("Alice", "1")
        self.assertTrue(result)
        self.assertNotIn("1", chat_data.messages)

        # Deletion when the message_id is not present should return False.
        result = chat_data.delete_message("Alice", "nonexistent")
        self.assertFalse(result)

        # If the sender key is not in message_id_by_user,
        # a KeyError is raised (since delete_message does not check for missing key).
        with self.assertRaises(KeyError):
            chat_data.delete_message("NonUser", "2")

        # Deleting an existing user should return True...
        self.assertTrue(chat_data.delete_user("Charlie"))
        self.assertNotIn("Charlie", chat_data.users)
        # ...and deleting a non-existent user returns False.
        self.assertFalse(chat_data.delete_user("NonUser"))

    def test_chat_data_model_dump_conversion(self):
        chat_data = ChatData()
        chat_data.add_user("Alice")
        chat_data.add_user("Bob")
        message = ChatMessage(
            sender="Alice", recipient="Bob", message="Test", message_id="3"
        )
        chat_data.add_message(message)
        dumped = chat_data.model_dump()

        # Check that sets have been converted to lists.
        self.assertIsInstance(dumped["users"], list)
        self.assertIsInstance(dumped["message_id_by_user"], dict)
        for key, val in dumped["message_id_by_user"].items():
            self.assertIsInstance(val, list)

        # Check that each ChatMessage's timestamp has been converted to a string.
        for mid, msg in dumped["messages"].items():
            self.assertIsInstance(msg["timestamp"], str)

    # ---------------------
    # Custom TLV encoding/decoding tests
    # ---------------------
    def test_custom_tlv_encoding_decoding(self):
        original_flag = utils.USE_CUSTOM_WIRE_PROTOCOL
        utils.USE_CUSTOM_WIRE_PROTOCOL = True
        try:
            nested_data = {
                "key1": "value",
                "key2": 123,
                "key3": True,
                "key4": 3.14,
                "key5": [1, "two", False, {"nested": "yes"}],
                "empty_list": [],
                "empty_dict": {},
                "username": "testuser",
                "password": "testpass",
            }
            client_packet = ClientPacket(
                type=MessageType.CREATE_USER_REQUEST, data=nested_data
            )
            serialized_packet = serialize_packet(client_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
            self.assertEqual(client_packet, deserialized_packet)
        finally:
            utils.USE_CUSTOM_WIRE_PROTOCOL = original_flag

    # ---------------------
    # Test deserialization of invalid JSON input.
    # ---------------------
    def test_deserialize_packet_invalid_json(self):
        # Ensure we are in JSON mode.
        utils.USE_CUSTOM_WIRE_PROTOCOL = False
        invalid_json_bytes = b"{invalid json}"
        with self.assertRaises(ValueError):
            deserialize_packet(invalid_json_bytes, ClientPacket)


if __name__ == "__main__":
    unittest.main()