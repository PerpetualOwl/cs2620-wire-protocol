import unittest
import json
import struct
import hashlib
import socket
import threading
import time
import uuid
import sys
import os
from datetime import datetime

# Import our application utilities.
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

# Import the server module in order to run the integration tests.
import server

# =========================
# Existing unit tests
# =========================

class TestSecureChat(unittest.TestCase):

    def setUp(self):
        # Generate a key pair for encryption/decryption tests.
        self.private_key, self.public_key = generate_key_pair()
        # Force JSON wire protocol in unit tests.
        utils.USE_CUSTOM_WIRE_PROTOCOL = False

    def tearDown(self):
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
            hash_password(123)  # non-string input

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
        with self.assertRaises(Exception):
            encrypt(b"not a valid PEM", b"message")

    def test_decrypt_invalid_data(self):
        with self.assertRaises(Exception):
            decrypt(self.private_key, b"random invalid data")

    # ---------------------
    # Packet serialization (JSON mode)
    # ---------------------
    def test_serialize_deserialize_packet_json(self):
        client_packet = ClientPacket(
            type=MessageType.CREATE_USER_REQUEST,
            data={"username": "testuser", "password": "testpass"},
        )
        serialized_packet = serialize_packet(client_packet)
        deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
        self.assertEqual(client_packet, deserialized_packet)

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
            client_packet = ClientPacket(
                type=MessageType.CREATE_USER_REQUEST,
                data={"username": "customuser", "password": "custompass"},
            )
            serialized_packet = serialize_packet(client_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
            self.assertEqual(client_packet, deserialized_packet)

            server_packet = ServerPacket(
                type=MessageType.PUBLIC_KEY_RESPONSE, data={"public_key": "some_key"}
            )
            serialized_packet = serialize_packet(server_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ServerPacket)
            self.assertEqual(server_packet, deserialized_packet)

            # When data is None, it decodes to an empty dict.
            client_packet = ClientPacket(
                type=MessageType.REQUEST_PUBLIC_KEY, data=None
            )
            serialized_packet = serialize_packet(client_packet)
            deserialized_packet = deserialize_packet(serialized_packet, ClientPacket)
            self.assertEqual(deserialized_packet.data, {})
        finally:
            utils.USE_CUSTOM_WIRE_PROTOCOL = original_flag

    def test_serialize_deserialize_packet_invalid_custom(self):
        original_flag = utils.USE_CUSTOM_WIRE_PROTOCOL
        utils.USE_CUSTOM_WIRE_PROTOCOL = True
        try:
            invalid_packet_bytes = struct.pack("!B", 255) + b"\x00"
            with self.assertRaises(ValueError):
                deserialize_packet(invalid_packet_bytes, ClientPacket)
        finally:
            utils.USE_CUSTOM_WIRE_PROTOCOL = original_flag

    # ---------------------
    # Model validator tests for Client/Server packets
    # ---------------------
    def test_client_packet_validator_missing_required_data(self):
        with self.assertRaises(ValueError):
            ClientPacket(
                type=MessageType.SEND_MESSAGE, data={"sender": "Alice"}
            )

    def test_server_packet_validator_missing_required_data(self):
        with self.assertRaises(ValueError):
            ServerPacket(type=MessageType.USER_ADDED, data={})

    # ---------------------
    # ChatMessage tests
    # ---------------------
    def test_chat_message(self):
        now = datetime.now()
        msg = ChatMessage(
            sender="Alice", recipient="Bob", message="Hello!", message_id="123", timestamp=now
        )
        self.assertEqual(msg.sender, "Alice")
        self.assertEqual(msg.recipient, "Bob")
        self.assertEqual(msg.message, "Hello!")

        dumped = msg.model_dump()
        self.assertIsInstance(dumped["timestamp"], str)
        with self.assertRaises(ValueError):
            ChatMessage(
                sender="Alice",
                recipient="Bob",
                message="Hi",
                message_id="456",
                my_datetime="invalid-datetime",
            )

    def test_chat_message_datetime_parsing(self):
        iso_time = "2023-10-31T13:45:00Z"
        msg = ChatMessage(
            sender="Alice", recipient="Bob", message="Hello", message_id="789", timestamp=datetime.now()
        )
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
            sender="Alice", recipient="Bob", message="Hi", message_id="1", timestamp=datetime.now()
        )
        chat_data.add_message(message)
        self.assertIn("1", chat_data.messages)

        # Adding a message automatically adds unknown users.
        message2 = ChatMessage(
            sender="Charlie", recipient="Dave", message="Hey", message_id="2", timestamp=datetime.now()
        )
        chat_data.add_message(message2)
        self.assertIn("Charlie", chat_data.users)
        self.assertIn("Dave", chat_data.users)

        filtered = chat_data.get_messages("Alice")
        self.assertIn("1", filtered.messages)
        self.assertNotIn("2", filtered.messages)
        
        # For backend deletion, if the provided sender is not authorized, it should return False.
        result = chat_data.delete_message("Bob", "1", True)
        self.assertFalse(result)

        # Valid deletion.
        result = chat_data.delete_message("Alice", "1")
        self.assertTrue(result)
        self.assertNotIn("1", chat_data.messages)

        # If message ID does not exist, return False.
        result = chat_data.delete_message("Alice", "nonexistent")
        self.assertFalse(result)
        
        self.assertTrue(chat_data.delete_user("Charlie"))
        self.assertNotIn("Charlie", chat_data.users)
        self.assertFalse(chat_data.delete_user("NonUser"))

    def test_chat_data_model_dump_conversion(self):
        chat_data = ChatData()
        chat_data.add_user("Alice")
        chat_data.add_user("Bob")
        message = ChatMessage(
            sender="Alice", recipient="Bob", message="Test", message_id="3", timestamp=datetime.now()
        )
        chat_data.add_message(message)
        dumped = chat_data.model_dump()
        self.assertIsInstance(dumped["users"], list)
        self.assertIsInstance(dumped["message_id_by_user"], dict)
        for key, val in dumped["message_id_by_user"].items():
            self.assertIsInstance(val, list)
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
        utils.USE_CUSTOM_WIRE_PROTOCOL = False
        invalid_json_bytes = b"{invalid json}"
        with self.assertRaises(ValueError):
            deserialize_packet(invalid_json_bytes, ClientPacket)


# =========================
# Integration and regression tests
# =========================

class TestIntegration(unittest.TestCase):
    """
    Integration tests run a server (in a daemon thread) and then create fake
    client connections to test full, end-to-end interactions.
    (We override utils.SERVER_IP and SERVER_PORT for testing.)
    """
    TEST_PORT = 33259
    SERVER_STARTUP_WAIT = 1  # seconds

    @classmethod
    def setUpClass(cls):
        # Override global connection details.
        utils.SERVER_IP = ""
        utils.SERVER_PORT = cls.TEST_PORT

        # Reset server globals.
        with server.global_lock:
            server.chat_data = ChatData()
            server.users.clear()
            server.authed_clients.clear()
            server.clients.clear()

        # Start the server in a daemon thread.
        cls.server_thread = threading.Thread(target=server.main, daemon=True)
        cls.server_thread.start()
        time.sleep(cls.SERVER_STARTUP_WAIT)

    @classmethod
    def tearDownClass(cls):
        pass  # Optionally restore original values.

    # Define FakeClient to mimic a real client.
    class FakeClient:
        def __init__(self):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(2)
            self.sock.connect((utils.SERVER_IP, utils.SERVER_PORT))
            self.server_public_key = None
            self.username = None
            self.password = None  # hashed password

        def request_public_key(self):
            packet = ClientPacket(type=MessageType.REQUEST_PUBLIC_KEY, data={})
            # Public key request is unencrypted.
            data = serialize_packet(packet)
            self.sock.sendall(data)
            rsp = self.sock.recv(65536)
            spacket = deserialize_packet(rsp, ServerPacket)
            if spacket.type == MessageType.PUBLIC_KEY_RESPONSE:
                self.server_public_key = spacket.data["public_key"].encode("utf-8")
            return spacket

        def send_encrypted_packet(self, packet: ClientPacket):
            if self.server_public_key is None:
                raise ValueError("Server public key not available.")
            data = encrypt(self.server_public_key, serialize_packet(packet))
            self.sock.sendall(data)

        def recv_packet(self):
            data = self.sock.recv(65536)
            return deserialize_packet(data, ServerPacket)

        def expect_packet(self, expected_type, timeout=2):
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    packet = self.recv_packet()
                except socket.timeout:
                    continue
                if packet.type == expected_type:
                    return packet
                # Discard any unexpected broadcast packets.
            raise Exception(f"Expected packet type {expected_type} not received in time.")

        def create_user(self, username, password):
            self.username = username
            self.password = hash_password(password)
            packet = ClientPacket(
                type=MessageType.CREATE_USER_REQUEST,
                data={"username": username, "password": self.password},
            )
            self.send_encrypted_packet(packet)
            return self.expect_packet(MessageType.CREATE_USER_RESPONSE)

        def send_message(self, recipient, message):
            packet = ClientPacket(
                type=MessageType.SEND_MESSAGE,
                data={"sender": self.username, "recipient": recipient, "message": message, "password": self.password},
            )
            self.send_encrypted_packet(packet)
            return self.expect_packet(MessageType.MESSAGE_RECEIVED)

        def request_messages(self):
            packet = ClientPacket(
                type=MessageType.REQUEST_MESSAGES,
                data={"sender": self.username, "password": self.password},
            )
            self.send_encrypted_packet(packet)
            return self.expect_packet(MessageType.INITIAL_CHATDATA)

        def request_unread_messages(self, num_messages):
            packet = ClientPacket(
                type=MessageType.REQUEST_UNREAD_MESSAGES,
                data={"username": self.username, "num_messages": str(num_messages), "password": self.password},
            )
            self.send_encrypted_packet(packet)
            return self.expect_packet(MessageType.UNREAD_MESSAGES_RESPONSE)

        def delete_message(self, message_id):
            packet = ClientPacket(
                type=MessageType.DELETE_MESSAGE,
                data={"username": self.username, "message_id": message_id, "password": self.password},
            )
            self.send_encrypted_packet(packet)
            return self.expect_packet(MessageType.MESSAGE_DELETED)

        def delete_account(self):
            packet = ClientPacket(
                type=MessageType.DELETE_ACCOUNT,
                data={"username": self.username, "password": self.password},
            )
            self.send_encrypted_packet(packet)
            return self.expect_packet(MessageType.USER_DELETED)

        def close(self):
            self.sock.close()

    # ---------------------
    # Integration test cases
    # ---------------------
    def test_create_user(self):
        client = self.FakeClient()
        rsp = client.request_public_key()
        self.assertEqual(rsp.type, MessageType.PUBLIC_KEY_RESPONSE)
        rsp2 = client.create_user("Alice", "alicepwd")
        self.assertEqual(rsp2.type, MessageType.CREATE_USER_RESPONSE)
        self.assertTrue(rsp2.data.get("success"))
        self.assertIn("created", rsp2.data.get("message").lower())
        self.assertIn("Alice", server.users)
        client.close()

    def test_create_existing_user_login(self):
        # First client creates user Bob.
        client1 = self.FakeClient()
        client1.request_public_key()
        rsp_create = client1.create_user("Bob", "bobpwd")
        self.assertTrue(rsp_create.data.get("success"))
        client1.close()

        # Second client logs in with the same credentials.
        client2 = self.FakeClient()
        client2.request_public_key()
        rsp_login = client2.create_user("Bob", "bobpwd")
        self.assertTrue(rsp_login.data.get("success"))
        self.assertIn("logged in", rsp_login.data.get("message").lower())
        client2.close()

    def test_send_message_online(self):
        clientA = self.FakeClient()
        clientB = self.FakeClient()
        clientA.request_public_key()
        clientB.request_public_key()
        rspA = clientA.create_user("Alice", "alicepwd")
        rspB = clientB.create_user("Charlie", "charliepwd")
        rsp_msg_A = clientA.send_message("Charlie", "Hello Charlie")
        self.assertEqual(rsp_msg_A.type, MessageType.MESSAGE_RECEIVED)
        msg_data = rsp_msg_A.data
        self.assertEqual(msg_data.get("sender"), "Alice")
        self.assertEqual(msg_data.get("recipient"), "Charlie")
        self.assertEqual(msg_data.get("message"), "Hello Charlie")
        # ClientB should also eventually get a MESSAGE_RECEIVED broadcast.
        rsp_msg_B = clientB.expect_packet(MessageType.MESSAGE_RECEIVED)
        self.assertEqual(rsp_msg_B.data.get("sender"), "Alice")
        self.assertEqual(rsp_msg_B.data.get("recipient"), "Charlie")
        self.assertEqual(rsp_msg_B.data.get("message"), "Hello Charlie")
        clientA.close()
        clientB.close()

    def test_send_message_offline_and_unread(self):
        # David stays online while Eve disconnects.
        clientA = self.FakeClient()
        clientA.request_public_key()
        rspA = clientA.create_user("David", "davidpwd")
        self.assertTrue(rspA.data.get("success"))

        clientB = self.FakeClient()
        clientB.request_public_key()
        rspB = clientB.create_user("Eve", "evepwd")
        self.assertTrue(rspB.data.get("success"))
        clientB.close()  # Eve goes offline

        # David sends a message to Eve.
        rsp_msg = clientA.send_message("Eve", "Hello Eve")
        self.assertEqual(rsp_msg.type, MessageType.MESSAGE_RECEIVED)

        # Reconnect Eve.
        clientB_new = self.FakeClient()
        clientB_new.request_public_key()
        rsp_login = clientB_new.create_user("Eve", "evepwd")
        self.assertTrue(rsp_login.data.get("success"))
        self.assertIn("unread", rsp_login.data.get("message").lower())
        rsp_unread = clientB_new.request_unread_messages(1)
        self.assertEqual(rsp_unread.type, MessageType.UNREAD_MESSAGES_RESPONSE)
        messages = rsp_unread.data.get("messages")
        self.assertIsInstance(messages, list)
        self.assertGreaterEqual(len(messages), 1)
        self.assertEqual(messages[0].get("sender"), "David")
        clientA.close()
        clientB_new.close()

    def test_delete_message(self):
        client_frank = self.FakeClient()
        client_grace = self.FakeClient()
        client_frank.request_public_key()
        client_grace.request_public_key()
        rsp_frank = client_frank.create_user("Frank", "frankpwd")
        rsp_grace = client_grace.create_user("Grace", "gracepwd")
        rsp_msg = client_frank.send_message("Grace", "Hi Grace")
        self.assertEqual(rsp_msg.type, MessageType.MESSAGE_RECEIVED)
        message_id = rsp_msg.data.get("message_id")
        self.assertIsNotNone(message_id)
        rsp_del = client_frank.delete_message(message_id)
        self.assertEqual(rsp_del.type, MessageType.MESSAGE_DELETED)
        self.assertNotIn(message_id, server.chat_data.messages)
        client_frank.close()
        client_grace.close()

    def test_delete_account(self):
        client_henry = self.FakeClient()
        client_irene = self.FakeClient()
        client_henry.request_public_key()
        client_irene.request_public_key()
        rsp_henry = client_henry.create_user("Henry", "henrypwd")
        rsp_irene = client_irene.create_user("Irene", "irenepwd")
        rsp_delacc = client_henry.delete_account()
        self.assertEqual(rsp_delacc.type, MessageType.USER_DELETED)
        self.assertEqual(rsp_delacc.data.get("username"), "Henry")
        rsp_broadcast = client_irene.expect_packet(MessageType.USER_DELETED)
        self.assertEqual(rsp_broadcast.data.get("username"), "Henry")
        self.assertNotIn("Henry", server.users)
        client_henry.close()
        client_irene.close()

    def test_user_added_broadcast(self):
        client_jack = self.FakeClient()
        client_jack.request_public_key()
        rsp_jack = client_jack.create_user("Jack", "jackpwd")
        self.assertTrue(rsp_jack.data.get("success"))
        client_kate = self.FakeClient()
        client_kate.request_public_key()
        rsp_kate = client_kate.create_user("Kate", "katepwd")
        self.assertTrue(rsp_kate.data.get("success"))
        rsp_bcast = client_jack.expect_packet(MessageType.USER_ADDED)
        self.assertEqual(rsp_bcast.data.get("username"), "Kate")
        client_jack.close()
        client_kate.close()

    def test_regression_invalid_encrypted_packet(self):
        fake_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fake_sock.settimeout(2)
        fake_sock.connect((utils.SERVER_IP, utils.SERVER_PORT))
        fake_sock.sendall(b"invalid encrypted content")
        try:
            data = fake_sock.recv(1024)
            self.assertTrue(data == b"" or data is None)
        except socket.timeout:
            pass
        finally:
            fake_sock.close()


# =========================
# Main entry for unittest
# =========================

if __name__ == "__main__":
    unittest.main()