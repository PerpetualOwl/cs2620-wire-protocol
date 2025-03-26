import unittest
import time
import uuid
import threading
import grpc
import sys
import os
import json
import tempfile
import shutil
from unittest.mock import MagicMock, patch, PropertyMock

# Import the application modules
import chat_pb2
import chat_pb2_grpc
import raft_pb2
import raft_pb2_grpc
from config import Config
from database import DatabaseManager
from raft import RaftNode, NodeState
from server import ChatServicer
from client import ChatClient, hash_password
from test_utils import TestDatabaseManager, create_in_memory_database, mock_raft_node

class TestChatServiceBasic(unittest.TestCase):
    """Unit tests for basic ChatServicer functionality using mocks"""
    
    def setUp(self):
        # Create mock dependencies
        self.db = MagicMock()
        self.raft_node = MagicMock()
        
        # Configure raft_node mock
        type(self.raft_node).state = PropertyMock(return_value=NodeState.LEADER)
        self.raft_node.replicate_log.return_value = True
        
        # Configure db mock
        self.db.validate_session.return_value = True
        self.db.get_user.side_effect = self._mock_get_user
        self.db.create_user.return_value = True
        self.db.delete_user.return_value = True
        self.db.list_users.return_value = ["user1", "user2"]
        self.db.save_message.return_value = True
        
        # Create the service with mocked dependencies
        self.servicer = ChatServicer(raft_node=self.raft_node, db=self.db)
        
        # Create a mock context
        self.context = MagicMock()
        
        # Store test data
        self.test_users = {}
        self.test_messages = {}
    
    def _mock_get_user(self, username):
        """Mock implementation of get_user"""
        if username in self.test_users:
            return self.test_users[username]
        return None
    
    def test_account_creation(self):
        """Test creating a new account"""
        # Setup
        username = "testuser"
        password_hash = "hashed_password"
        
        # Execute
        request = chat_pb2.CreateAccountRequest(
            username=username,
            password_hash=password_hash
        )
        response = self.servicer.CreateAccount(request, self.context)
        
        # Verify
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Account created successfully")
        self.assertFalse(response.account_exists)
        
        # Verify the raft_node was called to replicate the operation
        self.raft_node.replicate_log.assert_called_once()
        
        # Verify the database was called to create the user
        self.db.create_user.assert_called_once_with(username, password_hash)
    
    def test_duplicate_account_creation(self):
        """Test creating a duplicate account"""
        # Setup
        username = "testuser"
        password_hash = "hashed_password"
        
        # Add the user to our test data
        self.test_users[username] = {"username": username, "password_hash": password_hash}
        
        # Execute
        request = chat_pb2.CreateAccountRequest(
            username=username,
            password_hash="different_password"
        )
        response = self.servicer.CreateAccount(request, self.context)
        
        # Verify
        self.assertFalse(response.success)
        self.assertTrue(response.account_exists)
        
        # Verify the raft_node was not called to replicate the operation
        self.raft_node.replicate_log.assert_not_called()
    
    def test_login_success(self):
        """Test successful login"""
        # Setup
        username = "testuser"
        password_hash = "hashed_password"
        
        # Add the user to our test data
        self.test_users[username] = {"username": username, "password_hash": password_hash}
        
        # Configure the mock to create a session
        self.db.create_session.return_value = True
        
        # Execute
        request = chat_pb2.LoginRequest(
            username=username,
            password_hash=password_hash
        )
        response = self.servicer.Login(request, self.context)
        
        # Verify
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Login successful")
        self.assertIn(username, self.servicer.online_users)
        self.assertTrue(response.session_token)  # Should have a token
        
        # Verify the database was called to create a session
        self.db.create_session.assert_called_once()
    
    def test_login_invalid_username(self):
        """Test login with invalid username"""
        # Setup - no user in the database
        
        # Execute
        request = chat_pb2.LoginRequest(
            username="nonexistent",
            password_hash="hashed_password"
        )
        response = self.servicer.Login(request, self.context)
        
        # Verify
        self.assertFalse(response.success)
        self.assertEqual(response.message, "Invalid username")
        
        # Verify no session was created
        self.db.create_session.assert_not_called()
    
    def test_login_invalid_password(self):
        """Test login with invalid password"""
        # Setup
        username = "testuser"
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        
        # Add the user to our test data
        self.test_users[username] = {"username": username, "password_hash": correct_password}
        
        # Execute
        request = chat_pb2.LoginRequest(
            username=username,
            password_hash=wrong_password
        )
        response = self.servicer.Login(request, self.context)
        
        # Verify
        self.assertFalse(response.success)
        self.assertEqual(response.message, "Invalid password")
        
        # Verify no session was created
        self.db.create_session.assert_not_called()
    
    def test_send_message(self):
        """Test sending a message"""
        # Setup
        sender = "sender"
        recipient = "recipient"
        content = "Hello!"
        session_token = "test_token"
        
        # Add users to our test data
        self.test_users[sender] = {"username": sender, "password_hash": "hash1"}
        self.test_users[recipient] = {"username": recipient, "password_hash": "hash2"}
        
        # Configure mocks
        self.db.validate_session.return_value = True
        
        # Execute
        request = chat_pb2.SendMessageRequest(
            sender=sender,
            recipient=recipient,
            content=content,
            session_token=session_token
        )
        response = self.servicer.SendMessage(request, self.context)
        
        # Verify
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Message sent")
        self.assertTrue(response.message_id)  # Should have a message ID
        
        # Verify the raft_node was called to replicate the operation
        self.raft_node.replicate_log.assert_called_once()
        
        # Verify the database was called to save the message
        self.db.save_message.assert_called_once()
    
    def test_delete_account(self):
        """Test account deletion"""
        # Create account and session
        self.db.create_user("testuser", "password_hash")
        session_token = "test_token"
        self.db.create_session(session_token, "testuser")
        
        # Test account deletion
        request = chat_pb2.DeleteAccountRequest(
            username="testuser",
            password_hash="password_hash",
            session_token=session_token
        )
        response = self.servicer.DeleteAccount(request, self.context)
        
        self.assertTrue(response.success)
        self.assertIsNone(self.db.get_user("testuser"))  # User should be gone
    
    def test_send_message(self):
        """Test sending a message"""
        # Create sender and recipient accounts
        self.db.create_user.return_value = True
        
        # Important: Set up the get_user method to return a valid user when called with "recipient"
        def mock_get_user(username):
            if username == "recipient":
                return {"username": "recipient", "password_hash": "hash"}
            return None
        
        self.db.get_user.side_effect = mock_get_user
        self.db.validate_session.return_value = True
        self.db.save_message.return_value = True
        
        # Setup mock for raft node - IMPORTANT: set state to LEADER
        type(self.raft_node).state = PropertyMock(return_value=NodeState.LEADER)
        self.raft_node.replicate_log.return_value = True
        
        # Create session token
        session_token = "test_token"
        
        # Test sending a message
        request = chat_pb2.SendMessageRequest(
            sender="sender",
            recipient="recipient",
            content="Hello!",
            session_token=session_token
        )
        
        # Log the request for debugging
        print(f"SendMessage request: {request}")
        
        response = self.servicer.SendMessage(request, self.context)
        
        # Log the response for debugging
        print(f"SendMessage response: {response}")
        
        self.assertTrue(response.success)
        
        # Verify save_message was called with correct arguments
        self.db.save_message.assert_called_once()
    
    def test_list_accounts(self):
        """Test listing accounts with pattern matching"""
        # Create multiple accounts
        self.db.create_user("user1", "hash1")
        self.db.create_user("user2", "hash2")
        self.db.create_user("admin", "hash3")
        session_token = "test_token"
        self.db.create_session(session_token, "user1")
        
        # Test listing accounts with pattern
        request = chat_pb2.ListAccountsRequest(
            pattern="user*",
            page=1,
            page_size=10,
            session_token=session_token
        )
        response = self.servicer.ListAccounts(request, self.context)
        
        self.assertEqual(len(response.usernames), 2)
        self.assertIn("user1", response.usernames)
        self.assertIn("user2", response.usernames)
        self.assertNotIn("admin", response.usernames)
    
    def test_get_messages(self):
        """Test retrieving messages"""
        # Setup mocks
        self.db.get_user.side_effect = self._mock_get_user
        self.db.validate_session.return_value = True
        
        # Create mock messages
        timestamp = int(time.time())
        mock_messages = [
            {"message_id": "msg1", "sender": "sender", "recipient": "recipient", 
             "content": "Message 1", "timestamp": timestamp, "read": 0},
            {"message_id": "msg2", "sender": "sender", "recipient": "recipient", 
             "content": "Message 2", "timestamp": timestamp, "read": 0}
        ]
        self.db.get_messages.return_value = mock_messages
        
        # Test getting messages
        request = chat_pb2.GetMessagesRequest(
            username="recipient",
            limit=10,
            session_token="test_token"
        )
        response = self.servicer.GetMessages(request, self.context)
        
        # Verify response
        self.assertEqual(len(response.messages), 2)
        message_contents = [m.content for m in response.messages]
        self.assertIn("Message 1", message_contents)
        self.assertIn("Message 2", message_contents)
        
        # Verify get_messages was called with correct arguments
        self.db.get_messages.assert_called_once_with("recipient", 10)
    
    def test_delete_messages(self):
        """Test deleting messages"""
        # Setup mocks
        self.db.get_user.side_effect = self._mock_get_user
        self.db.validate_session.return_value = True
        self.db.delete_messages.return_value = 1
        self.raft_node.replicate_log.return_value = True
        
        # Create mock messages for verification after deletion
        timestamp = int(time.time())
        mock_messages = [
            {"message_id": "msg2", "sender": "sender", "recipient": "recipient", 
             "content": "Message 2", "timestamp": timestamp, "read": 0}
        ]
        
        # Test deleting one message
        request = chat_pb2.DeleteMessagesRequest(
            username="recipient",
            message_ids=["msg1"],
            session_token="test_token"
        )
        response = self.servicer.DeleteMessages(request, self.context)
        
        # Verify response
        self.assertTrue(response.success)
        self.assertEqual(response.deleted_count, 1)
        
        # Setup mock for get_messages after deletion
        self.db.get_messages.return_value = mock_messages
        
        # Verify only one message remains
        messages = self.db.get_messages("recipient")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["message_id"], "msg2")
        
        # Verify delete_messages was called with correct arguments
        self.db.delete_messages.assert_called_once()


class TestDatabaseManagerOperations(unittest.TestCase):
    """Unit tests for the DatabaseManager class"""
    
    def setUp(self):
        # Use the TestDatabaseManager with in-memory database
        self.db = create_in_memory_database()
    
    def tearDown(self):
        # No need to clean up in-memory database
        pass
    
    def test_create_and_get_user(self):
        """Test creating and retrieving a user"""
        # Create a user
        self.assertTrue(self.db.create_user("testuser", "password_hash"))
        
        # Get the user
        user = self.db.get_user("testuser")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "testuser")
        self.assertEqual(user["password_hash"], "password_hash")
    
    def test_delete_user(self):
        """Test deleting a user"""
        # Create a user
        self.db.create_user("testuser", "password_hash")
        
        # Delete the user
        self.assertTrue(self.db.delete_user("testuser"))
        
        # Verify user is gone
        self.assertIsNone(self.db.get_user("testuser"))
    
    def test_list_users(self):
        """Test listing users with pattern matching"""
        # Create users
        self.db.create_user("user1", "hash1")
        self.db.create_user("user2", "hash2")
        self.db.create_user("admin", "hash3")
        
        # List all users
        all_users = self.db.list_users()
        self.assertEqual(len(all_users), 3)
        self.assertIn("user1", all_users)
        self.assertIn("user2", all_users)
        self.assertIn("admin", all_users)
        
        # List users with pattern
        user_pattern = self.db.list_users("user%")
        self.assertEqual(len(user_pattern), 2)
        self.assertIn("user1", user_pattern)
        self.assertIn("user2", user_pattern)
        self.assertNotIn("admin", user_pattern)
    
    def test_message_operations(self):
        """Test message operations (save, get, mark as read, delete)"""
        # Create users
        self.db.create_user("sender", "hash1")
        self.db.create_user("recipient", "hash2")
        
        # Save messages
        message_id1 = "msg1"
        message_id2 = "msg2"
        timestamp = int(time.time())
        
        self.assertTrue(self.db.save_message(message_id1, "sender", "recipient", "Message 1", timestamp))
        self.assertTrue(self.db.save_message(message_id2, "sender", "recipient", "Message 2", timestamp))
        
        # Get messages
        messages = self.db.get_messages("recipient")
        self.assertEqual(len(messages), 2)
        
        # Mark messages as read
        self.db.mark_messages_read([message_id1])
        
        # Delete a message
        self.db.delete_messages([message_id1])
        
        # Verify only one message remains
        messages = self.db.get_messages("recipient")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["message_id"], message_id2)
    
    def test_session_operations(self):
        """Test session operations (create, validate, delete)"""
        # Create a user
        self.db.create_user("testuser", "password_hash")
        
        # Create a session
        session_token = "test_token"
        self.assertTrue(self.db.create_session(session_token, "testuser"))
        
        # Validate the session
        self.assertTrue(self.db.validate_session(session_token, "testuser"))
        self.assertTrue(self.db.validate_session(session_token))  # Without username
        
        # Delete the session
        self.db.delete_session(session_token)
        
        # Verify session is gone
        self.assertFalse(self.db.validate_session(session_token))
    
    def test_raft_state_operations(self):
        """Test Raft state operations"""
        # Save state
        self.db.save_raft_state("current_term", 5)
        self.db.save_raft_state("voted_for", "server2")
        
        # Get state
        self.assertEqual(self.db.get_raft_state("current_term"), 5)
        self.assertEqual(self.db.get_raft_state("voted_for"), "server2")
        
        # Update state
        self.db.save_raft_state("current_term", 6)
        self.assertEqual(self.db.get_raft_state("current_term"), 6)
    
    def test_raft_log_operations(self):
        """Test Raft log operations"""
        # Append log entries
        term = 1
        operation_type = "CREATE_USER"
        data = b"testuser:password_hash"
        
        log_index = self.db.append_raft_log(term, operation_type, data)
        self.assertGreater(log_index, 0)
        
        # Get log entry
        entry = self.db.get_raft_log_entry(log_index)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["term"], term)
        self.assertEqual(entry["operation_type"], operation_type)
        self.assertEqual(entry["data"], data)


class TestChatClient(unittest.TestCase):
    """Unit tests for the ChatClient class"""
    
    def setUp(self):
        # Create a test configuration with mocked values
        self.config = MagicMock()
        self.config.server_list = [MagicMock(client_address="localhost:50051")]
        
        # Mock the gRPC stub
        self.stub = MagicMock()
        
        # Create a client with mocked dependencies
        with patch.object(grpc, 'insecure_channel'):
            self.client = ChatClient(self.config)
            self.client._connect_to_server = MagicMock(return_value=True)
            self.client.stub = self.stub
            self.client.current_server = self.config.server_list[0]
            self.client.session_token = "test_token"
            self.client.username = "testuser"
    
    def test_create_account(self):
        """Test creating an account"""
        # Setup
        username = "newuser"
        password = "password123"
        
        # Configure mock response
        mock_response = MagicMock()
        mock_response.success = True
        self.stub.CreateAccount.return_value = mock_response
        
        # Execute
        result = self.client.create_account(username, password)
        
        # Verify
        self.assertTrue(result)
        self.stub.CreateAccount.assert_called_once()
        
        # Check that the password was hashed
        args = self.stub.CreateAccount.call_args[0][0]
        self.assertEqual(args.username, username)
        self.assertNotEqual(args.password_hash, password)  # Should be hashed
    
    def test_login(self):
        """Test logging in"""
        # Setup
        username = "testuser"
        password = "password123"
        session_token = "new_token"
        
        # Configure mock response
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.session_token = session_token
        self.stub.Login.return_value = mock_response
        
        # Execute
        result = self.client.login(username, password)
        
        # Verify
        self.assertTrue(result)
        self.assertEqual(self.client.session_token, session_token)
        self.assertEqual(self.client.username, username)
        self.stub.Login.assert_called_once()
        
        # Check that the password was hashed
        args = self.stub.Login.call_args[0][0]
        self.assertEqual(args.username, username)
        self.assertNotEqual(args.password_hash, password)  # Should be hashed
    
    def test_send_message(self):
        """Test sending a message"""
        # Setup
        recipient = "recipient"
        content = "Hello!"
        message_id = "msg123"
        
        # Configure mock response
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.message_id = message_id
        self.stub.SendMessage.return_value = mock_response
        
        # Execute
        result = self.client.send_message(recipient, content)
        
        # Verify
        self.assertTrue(result)
        self.stub.SendMessage.assert_called_once()
        
        # Check the request parameters
        args = self.stub.SendMessage.call_args[0][0]
        self.assertEqual(args.sender, self.client.username)
        self.assertEqual(args.recipient, recipient)
        self.assertEqual(args.content, content)
        self.assertEqual(args.session_token, self.client.session_token)
    
    def test_get_messages(self):
        """Test getting messages"""
        # Setup
        message1 = MagicMock()
        message1.message_id = "msg1"
        message1.content = "Hello"
        
        message2 = MagicMock()
        message2.message_id = "msg2"
        message2.content = "World"
        
        # Configure mock response
        mock_response = MagicMock()
        mock_response.messages = [message1, message2]
        self.stub.GetMessages.return_value = mock_response
        
        # Execute
        messages = self.client.get_messages()
        
        # Verify
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].message_id, "msg1")
        self.assertEqual(messages[1].message_id, "msg2")
        self.stub.GetMessages.assert_called_once()
        
        # Check the request parameters
        args = self.stub.GetMessages.call_args[0][0]
        self.assertEqual(args.username, self.client.username)
        self.assertEqual(args.session_token, self.client.session_token)
    



import sqlite3

if __name__ == '__main__':
    unittest.main()
    



if __name__ == '__main__':
    unittest.main()
