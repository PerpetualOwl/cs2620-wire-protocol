import unittest
import time
import uuid
import threading
import grpc
import sys
import os
from unittest.mock import MagicMock, patch
import tempfile

# Import the application modules
import chat_pb2
import chat_pb2_grpc
from server import ChatServicer, serve
from client import ChatClient, LoginDialog, MessageReceiver, hash_password

# PyQt5 imports for client testing
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt, QTimer

class TestChatServiceBasic(unittest.TestCase):
    """Unit tests for basic ChatServicer functionality"""
    
    def setUp(self):
        self.servicer = ChatServicer()
        # Create a mock context
        self.context = MagicMock()
        
    def test_account_creation(self):
        # Test creating a new account
        request = chat_pb2.CreateAccountRequest(
            username="testuser",
            password_hash="hashed_password"
        )
        response = self.servicer.CreateAccount(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Account created successfully")
        self.assertFalse(response.account_exists)
        self.assertIn("testuser", self.servicer.accounts)
        
    def test_duplicate_account_creation(self):
        # Setup - Create account first
        self.servicer.accounts["testuser"] = {"password_hash": "hashed_password"}
        self.servicer.messages["testuser"] = []
        
        # Test creating a duplicate account
        request = chat_pb2.CreateAccountRequest(
            username="testuser",
            password_hash="different_password"
        )
        response = self.servicer.CreateAccount(request, self.context)
        
        self.assertFalse(response.success)
        self.assertTrue(response.account_exists)
        
    def test_login_success(self):
        # Setup - Create account first
        self.servicer.accounts["testuser"] = {"password_hash": "hashed_password"}
        self.servicer.messages["testuser"] = []
        
        # Test login
        request = chat_pb2.LoginRequest(
            username="testuser",
            password_hash="hashed_password"
        )
        response = self.servicer.Login(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Login successful")
        self.assertIn("testuser", self.servicer.online_users)
        self.assertTrue(response.session_token)  # Should have a token
        
    def test_login_invalid_username(self):
        # Test login with invalid username
        request = chat_pb2.LoginRequest(
            username="nonexistent",
            password_hash="hashed_password"
        )
        response = self.servicer.Login(request, self.context)
        
        self.assertFalse(response.success)
        self.assertEqual(response.message, "Invalid username")
        
    def test_login_invalid_password(self):
        # Setup - Create account first
        self.servicer.accounts["testuser"] = {"password_hash": "correct_password"}
        self.servicer.messages["testuser"] = []
        
        # Test login with invalid password
        request = chat_pb2.LoginRequest(
            username="testuser",
            password_hash="wrong_password"
        )
        response = self.servicer.Login(request, self.context)
        
        self.assertFalse(response.success)
        self.assertEqual(response.message, "Invalid password")
        
    def test_session_validation(self):
        # Setup a session
        token = "test_token"
        username = "testuser"
        with self.servicer.session_lock:
            self.servicer.sessions[token] = username
            
        # Test validation
        self.assertTrue(self.servicer.validate_session(token))
        self.assertTrue(self.servicer.validate_session(token, username))
        self.assertFalse(self.servicer.validate_session(token, "wrong_user"))
        self.assertFalse(self.servicer.validate_session("wrong_token"))
        
    def test_pattern_matching(self):
        # Test wildcard pattern matching
        self.assertTrue(self.servicer._match_pattern("user1", "user*"))
        self.assertTrue(self.servicer._match_pattern("user123", "user???"))
        self.assertFalse(self.servicer._match_pattern("admin", "user*"))
        self.assertTrue(self.servicer._match_pattern("anything", ""))  # Empty pattern matches all
        
    def test_delete_account(self):
        # Setup - Create account and session
        username = "testuser"
        password_hash = "hashed_password"
        self.servicer.accounts[username] = {"password_hash": password_hash}
        self.servicer.messages[username] = []
        token = self.servicer._generate_session_token(username)
        
        # Test account deletion
        request = chat_pb2.DeleteAccountRequest(
            username=username,
            password_hash=password_hash,
            session_token=token
        )
        response = self.servicer.DeleteAccount(request, self.context)
        
        self.assertTrue(response.success)
        self.assertNotIn(username, self.servicer.accounts)
        self.assertNotIn(username, self.servicer.messages)
        
    def test_delete_account_invalid_password(self):
        # Setup - Create account and session
        username = "testuser"
        password_hash = "hashed_password"
        self.servicer.accounts[username] = {"password_hash": password_hash}
        self.servicer.messages[username] = []
        token = self.servicer._generate_session_token(username)
        
        # Test deletion with wrong password
        request = chat_pb2.DeleteAccountRequest(
            username=username,
            password_hash="wrong_password",
            session_token=token
        )
        response = self.servicer.DeleteAccount(request, self.context)
        
        self.assertFalse(response.success)
        self.assertIn(username, self.servicer.accounts)
        
    def test_send_message(self):
        # Setup - Create sender and recipient accounts
        sender = "sender"
        recipient = "recipient"
        self.servicer.accounts[sender] = {"password_hash": "hash1"}
        self.servicer.accounts[recipient] = {"password_hash": "hash2"}
        self.servicer.messages[recipient] = []
        token = self.servicer._generate_session_token(sender)
        
        # Test sending a message
        request = chat_pb2.SendMessageRequest(
            sender=sender,
            recipient=recipient,
            content="Hello!",
            session_token=token
        )
        response = self.servicer.SendMessage(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(len(self.servicer.messages[recipient]), 1)
        self.assertEqual(self.servicer.messages[recipient][0].content, "Hello!")
        
    def test_list_accounts(self):
        # Setup - Create multiple accounts
        self.servicer.accounts = {
            "user1": {"password_hash": "hash1"},
            "user2": {"password_hash": "hash2"},
            "admin": {"password_hash": "hash3"}
        }
        token = self.servicer._generate_session_token("user1")
        
        # Test listing accounts with pattern
        request = chat_pb2.ListAccountsRequest(
            pattern="user*",
            page=1,
            page_size=10,
            session_token=token
        )
        response = self.servicer.ListAccounts(request, self.context)
        
        self.assertEqual(len(response.usernames), 2)
        self.assertIn("user1", response.usernames)
        self.assertIn("user2", response.usernames)
        self.assertNotIn("admin", response.usernames)
        
    def test_hash_password(self):
        # Test password hashing function
        password = "password123"
        hashed = hash_password(password)
        
        # Should be a valid SHA-256 hash (64 chars)
        self.assertEqual(len(hashed), 64)
        # Hashing should be consistent
        self.assertEqual(hashed, hash_password(password))
        # Different passwords should have different hashes
        self.assertNotEqual(hashed, hash_password("different"))


class TestChatServiceMessages(unittest.TestCase):
    """Unit tests for message-related functionality"""
    
    def setUp(self):
        self.servicer = ChatServicer()
        self.context = MagicMock()
        
        # Setup common test accounts
        self.sender = "sender"
        self.recipient = "recipient"
        self.servicer.accounts[self.sender] = {"password_hash": "hash1"}
        self.servicer.accounts[self.recipient] = {"password_hash": "hash2"}
        self.servicer.messages[self.sender] = []
        self.servicer.messages[self.recipient] = []
        self.token = self.servicer._generate_session_token(self.sender)
        
    def test_get_messages_empty(self):
        # Test getting messages when there are none
        request = chat_pb2.GetMessagesRequest(
            username=self.sender,
            limit=10,
            session_token=self.token
        )
        response = self.servicer.GetMessages(request, self.context)
        
        self.assertEqual(len(response.messages), 0)
        
    def test_get_messages_with_content(self):
        # Setup - Create some messages
        for i in range(5):
            message = chat_pb2.Message(
                message_id=f"msg{i}",
                sender=self.recipient,
                recipient=self.sender,
                content=f"Message {i}",
                timestamp=int(time.time()),
                read=False
            )
            self.servicer.messages[self.sender].append(message)
            
        # Test getting messages
        request = chat_pb2.GetMessagesRequest(
            username=self.sender,
            limit=3,  # Get only first 3
            session_token=self.token
        )
        response = self.servicer.GetMessages(request, self.context)
        
        self.assertEqual(len(response.messages), 3)
        self.assertEqual(response.remaining_messages, 2)
        self.assertEqual(response.messages[0].content, "Message 0")
        self.assertEqual(response.messages[2].content, "Message 2")
        
        # Messages should be marked as read
        for msg in response.messages:
            self.assertTrue(msg.read)
            
        # Messages should be removed from storage
        self.assertEqual(len(self.servicer.messages[self.sender]), 2)
        
    def test_delete_messages(self):
        # Setup - Create some messages
        message_ids = []
        for i in range(5):
            msg_id = f"msg{i}"
            message_ids.append(msg_id)
            message = chat_pb2.Message(
                message_id=msg_id,
                sender=self.recipient,
                recipient=self.sender,
                content=f"Message {i}",
                timestamp=int(time.time()),
                read=False
            )
            self.servicer.messages[self.sender].append(message)
            
        # Test deleting specific messages
        request = chat_pb2.DeleteMessagesRequest(
            username=self.sender,
            message_ids=message_ids[1:3],  # Delete messages 1 and 2
            session_token=self.token
        )
        response = self.servicer.DeleteMessages(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(response.deleted_count, 2)
        self.assertEqual(len(self.servicer.messages[self.sender]), 3)
        
        # Check that the right messages were deleted
        remaining_ids = [msg.message_id for msg in self.servicer.messages[self.sender]]
        self.assertIn("msg0", remaining_ids)
        self.assertNotIn("msg1", remaining_ids)
        self.assertNotIn("msg2", remaining_ids)
        self.assertIn("msg3", remaining_ids)
        self.assertIn("msg4", remaining_ids)
        
    def test_delete_all_messages(self):
        # Setup - Create some messages
        message_ids = []
        for i in range(5):
            msg_id = f"msg{i}"
            message_ids.append(msg_id)
            message = chat_pb2.Message(
                message_id=msg_id,
                sender=self.recipient,
                recipient=self.sender,
                content=f"Message {i}",
                timestamp=int(time.time()),
                read=False
            )
            self.servicer.messages[self.sender].append(message)
            
        # Test deleting all messages
        request = chat_pb2.DeleteMessagesRequest(
            username=self.sender,
            message_ids=message_ids,
            session_token=self.token
        )
        response = self.servicer.DeleteMessages(request, self.context)
        
        self.assertTrue(response.success)
        self.assertEqual(response.deleted_count, 5)
        self.assertEqual(len(self.servicer.messages[self.sender]), 0)

class TestMessageReceiver(unittest.TestCase):
    """Tests for the client-side message receiver thread"""
    
    def setUp(self):
        self.stub = MagicMock()
        self.username = "testuser"
        self.session_token = "testsession"
        
    def test_message_receiver_init(self):
        # Test initialization
        receiver = MessageReceiver(self.stub, self.username, self.session_token)
        self.assertEqual(receiver.username, self.username)
        self.assertEqual(receiver.session_token, self.session_token)
        self.assertTrue(receiver.running)
        
    @patch('time.sleep', return_value=None)  # Mock sleep to speed up the test
    def test_message_receiver_run(self, mock_sleep):
        # Setup mock response for ReceiveMessages
        test_message = chat_pb2.Message(
            message_id="testmsg",
            sender="sender",
            recipient=self.username,
            content="Test message",
            timestamp=int(time.time()),
            read=False
        )
        self.stub.ReceiveMessages.return_value = [test_message]
        
        # Create and start receiver
        receiver = MessageReceiver(self.stub, self.username, self.session_token)
        
        # Mock the emit signal
        receiver.message_received = MagicMock()
        
        # Run in a separate thread that we can control
        thread = threading.Thread(target=receiver.run)
        thread.daemon = True
        thread.start()
        
        # Wait a bit for the receiver to process
        time.sleep(0.1)
        
        # Stop the receiver
        receiver.stop()
        thread.join(timeout=1)
        
        # Verify the stub was called correctly
        self.stub.ReceiveMessages.assert_called_once()
        request = self.stub.ReceiveMessages.call_args[0][0]
        self.assertEqual(request.username, self.username)
        self.assertEqual(request.session_token, self.session_token)
        
        # Verify message was emitted
        receiver.message_received.emit.assert_called_with(test_message)


class TestIntegration(unittest.TestCase):
    """Integration tests for server and client interaction"""
    
    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=serve)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        
        # Wait for server to start
        time.sleep(1)
        
        # Create gRPC channel and stub for tests
        cls.channel = grpc.insecure_channel('localhost:50051')
        cls.stub = chat_pb2_grpc.ChatServiceStub(cls.channel)
        
    def setUp(self):
        # Generate unique usernames for each test
        self.test_id = str(uuid.uuid4())[:8]
        self.username1 = f"user1_{self.test_id}"
        self.username2 = f"user2_{self.test_id}"
        self.password = "testpass"
        self.password_hash = hash_password(self.password)
        
    def test_account_lifecycle(self):
        # 1. Create accounts
        create_response1 = self.stub.CreateAccount(chat_pb2.CreateAccountRequest(
            username=self.username1,
            password_hash=self.password_hash
        ))
        self.assertTrue(create_response1.success)
        
        create_response2 = self.stub.CreateAccount(chat_pb2.CreateAccountRequest(
            username=self.username2,
            password_hash=self.password_hash
        ))
        self.assertTrue(create_response2.success)
        
        # 2. Login to accounts
        login_response1 = self.stub.Login(chat_pb2.LoginRequest(
            username=self.username1,
            password_hash=self.password_hash
        ))
        self.assertTrue(login_response1.success)
        session_token1 = login_response1.session_token
        
        login_response2 = self.stub.Login(chat_pb2.LoginRequest(
            username=self.username2,
            password_hash=self.password_hash
        ))
        self.assertTrue(login_response2.success)
        session_token2 = login_response2.session_token
        
        # 3. Send messages between users
        send_response = self.stub.SendMessage(chat_pb2.SendMessageRequest(
            sender=self.username1,
            recipient=self.username2,
            content=f"Hello from {self.username1}!",
            session_token=session_token1
        ))
        self.assertTrue(send_response.success)
        message_id = send_response.message_id
        
        # 4. Get messages
        get_response = self.stub.GetMessages(chat_pb2.GetMessagesRequest(
            username=self.username2,
            limit=10,
            session_token=session_token2
        ))
        self.assertEqual(len(get_response.messages), 1)
        self.assertEqual(get_response.messages[0].content, f"Hello from {self.username1}!")
        
        # 5. Delete messages
        delete_response = self.stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(
            username=self.username2,
            message_ids=[message_id],
            session_token=session_token2
        ))
        self.assertTrue(delete_response.success)
        
        # 6. List accounts
        list_response = self.stub.ListAccounts(chat_pb2.ListAccountsRequest(
            pattern=f"user*_{self.test_id}",
            page=1,
            page_size=10,
            session_token=session_token1
        ))
        self.assertEqual(len(list_response.usernames), 2)
        self.assertIn(self.username1, list_response.usernames)
        self.assertIn(self.username2, list_response.usernames)
        
        # 7. Delete accounts
        delete_account_response1 = self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(
            username=self.username1,
            password_hash=self.password_hash,
            session_token=session_token1
        ))
        self.assertTrue(delete_account_response1.success)
        
        delete_account_response2 = self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(
            username=self.username2,
            password_hash=self.password_hash,
            session_token=session_token2
        ))
        self.assertTrue(delete_account_response2.success)
        
    def test_real_time_messaging(self):
        # 1. Create accounts
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(
            username=self.username1,
            password_hash=self.password_hash
        ))
        self.stub.CreateAccount(chat_pb2.CreateAccountRequest(
            username=self.username2,
            password_hash=self.password_hash
        ))
        
        # 2. Login to accounts
        login_response1 = self.stub.Login(chat_pb2.LoginRequest(
            username=self.username1,
            password_hash=self.password_hash
        ))
        session_token1 = login_response1.session_token
        
        login_response2 = self.stub.Login(chat_pb2.LoginRequest(
            username=self.username2,
            password_hash=self.password_hash
        ))
        session_token2 = login_response2.session_token
        
        # 3. Start receiving messages for user2
        receive_request = chat_pb2.ReceiveMessagesRequest(
            username=self.username2,
            session_token=session_token2
        )
        
        # Use a queue to store messages received in the background thread
        received_messages = []
        stop_event = threading.Event()
        
        def receive_messages():
            try:
                for message in self.stub.ReceiveMessages(receive_request):
                    received_messages.append(message)
                    if stop_event.is_set():
                        break
            except Exception as e:
                print(f"Error in receive_messages: {e}")
                
        # Start the receiver thread
        receiver_thread = threading.Thread(target=receive_messages)
        receiver_thread.daemon = True
        receiver_thread.start()
        
        # Give the stream time to set up
        time.sleep(0.5)
        
        # 4. Send messages from user1 to user2
        test_message = f"Real-time message from {self.username1}"
        self.stub.SendMessage(chat_pb2.SendMessageRequest(
            sender=self.username1,
            recipient=self.username2,
            content=test_message,
            session_token=session_token1
        ))
        
        # Give the message time to be delivered
        time.sleep(0.5)
        
        # 5. Stop the receiver thread
        stop_event.set()
        
        # 6. Verify the message was received
        self.assertEqual(len(received_messages), 1)
        self.assertEqual(received_messages[0].content, test_message)
        
        # 7. Clean up
        self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(
            username=self.username1,
            password_hash=self.password_hash,
            session_token=session_token1
        ))
        self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(
            username=self.username2,
            password_hash=self.password_hash,
            session_token=session_token2
        ))


# We'll use PyQt5's QApplication instance for UI tests
app = None

class TestLoginDialog(unittest.TestCase):
    """Tests for the LoginDialog UI component"""
    
    @classmethod
    def setUpClass(cls):
        global app
        # Create QApplication instance
        if QApplication.instance() is None:
            app = QApplication(sys.argv)
        else:
            app = QApplication.instance()
    
    def setUp(self):
        self.dialog = LoginDialog()
        
    def test_login_mode(self):
        # Test initial state
        self.assertFalse(self.dialog.create_mode)
        
        # Fill in credentials
        self.dialog.username_input.setText("testuser")
        self.dialog.password_input.setText("testpass")
        
        # Simulate login button click
        QTest.mouseClick(self.dialog.login_button, Qt.LeftButton)
        
        # Check credentials and mode
        username, password_hash, create_mode = self.dialog.get_credentials()
        self.assertEqual(username, "testuser")
        self.assertEqual(password_hash, hash_password("testpass"))
        self.assertFalse(create_mode)
        
    def test_create_account_mode(self):
        # Fill in credentials
        self.dialog.username_input.setText("newuser")
        self.dialog.password_input.setText("newpass")
        
        # Simulate create account button click
        QTest.mouseClick(self.dialog.create_button, Qt.LeftButton)
        
        # Check credentials and mode
        username, password_hash, create_mode = self.dialog.get_credentials()
        self.assertEqual(username, "newuser")
        self.assertEqual(password_hash, hash_password("newpass"))
        self.assertTrue(create_mode)


@unittest.skipIf(QApplication.instance() is None, "Requires QApplication")
class TestChatClientUI(unittest.TestCase):
    """Tests for the ChatClient UI without actual server communication"""
    
    @classmethod
    def setUpClass(cls):
        global app
        # Create QApplication instance if needed
        if QApplication.instance() is None:
            app = QApplication(sys.argv)
        else:
            app = QApplication.instance()
    
    def setUp(self):
        # Create the client with mocked server connection
        self.client = ChatClient()
        self.client.stub = MagicMock()
        self.client.session_token = "test_token"
        self.client.username = "testuser"
        
    def test_initial_state(self):
        # Test initial window state
        self.assertEqual(self.client.windowTitle(), "gRPC Chat Client")
        self.assertEqual(self.client.stacked_widget.currentWidget(), self.client.login_widget)
        
    def test_display_message_content(self):
        # Create a mock message and message list item
        message = chat_pb2.Message(
            message_id="test_id",
            sender="sender",
            recipient="recipient", 
            content="Test message content",
            timestamp=int(time.time()),
            read=False
        )
        
        # Store the message in the client's message data dict
        self.client.messages_data["test_id"] = message
        
        # Create a mock MessageListItem
        class MockItem:
            def __init__(self):
                self.message_id = "test_id"
                
        mock_item = MockItem()
        
        # Call the display message method
        self.client.display_message_content(mock_item)
        
        # Check that the message display was updated
        display_text = self.client.message_display.toPlainText()
        self.assertIn("Test message content", display_text)
        self.assertIn("sender", display_text)
        
    def test_show_users_tab(self):
        # Mock the search_users method
        self.client.search_users = MagicMock()
        
        # Call the method
        self.client.show_users_tab()
        
        # Check that the tab was changed and search method called
        self.assertEqual(self.client.tabs.currentWidget(), self.client.users_tab)
        self.client.search_users.assert_called_once()
        
    def test_send_message(self):
        # Set up the test with recipient and content
        self.client.recipient_input.setText("recipient")
        self.client.message_input.setPlainText("Hello, recipient!")
        
        # Mock the stub's SendMessage method
        self.client.stub.SendMessage.return_value = chat_pb2.SendMessageResponse(
            success=True,
            message="Message sent",
            message_id="new_msg_id"
        )
        
        # Mock QMessageBox.information to avoid dialog
        with patch('PyQt5.QtWidgets.QMessageBox.information', return_value=None):
            # Call the send message method
            self.client.send_message()
            
        # Verify the stub was called with correct parameters
        self.client.stub.SendMessage.assert_called_once()
        request = self.client.stub.SendMessage.call_args[0][0]
        self.assertEqual(request.sender, "testuser")
        self.assertEqual(request.recipient, "recipient")
        self.assertEqual(request.content, "Hello, recipient!")
        self.assertEqual(request.session_token, "test_token")
        
        # Verify the message input was cleared
        self.assertEqual(self.client.message_input.toPlainText(), "")
        
    def test_select_user(self):
        # Create a mock list item
        class MockUserItem:
            def text(self):
                return "selected_user"
                
        mock_item = MockUserItem()
        
        # Call the method
        self.client.select_user(mock_item)
        
        # Check that the recipient was set and tab changed
        self.assertEqual(self.client.recipient_input.text(), "selected_user")
        self.assertEqual(self.client.tabs.currentWidget(), self.client.send_tab)


class TestRegressionIssues(unittest.TestCase):
    """Tests for specific regression issues that have been fixed"""
    
    def setUp(self):
        # For regression tests we use a fresh servicer instance
        self.servicer = ChatServicer()
        self.context = MagicMock()
        self.context.is_active.return_value = True
    
    def test_delete_account_removes_sender_messages(self):
        # Create two accounts A and B
        usernameA = "A_reg"
        usernameB = "B_reg"
        password_hash = "hashed"
        
        self.servicer.accounts[usernameA] = {"password_hash": password_hash}
        self.servicer.messages[usernameA] = []
        self.servicer.accounts[usernameB] = {"password_hash": password_hash}
        self.servicer.messages[usernameB] = []
        
        # Generate sessions
        tokenA = self.servicer._generate_session_token(usernameA)
        tokenB = self.servicer._generate_session_token(usernameB)
        
        # Send message from A to B
        send_req = chat_pb2.SendMessageRequest(
            sender=usernameA,
            recipient=usernameB,
            content="Message from A to B",
            session_token=tokenA
        )
        send_response = self.servicer.SendMessage(send_req, self.context)
        self.assertTrue(send_response.success)
        self.assertEqual(len(self.servicer.messages[usernameB]), 1)
        
        # Delete account A
        delete_req = chat_pb2.DeleteAccountRequest(
            username=usernameA,
            password_hash=password_hash,
            session_token=tokenA
        )
        del_response = self.servicer.DeleteAccount(delete_req, self.context)
        self.assertTrue(del_response.success)
        
        # Ensure that in account B's messages, no message from A remains
        for msg in self.servicer.messages[usernameB]:
            self.assertNotEqual(msg.sender, usernameA)
    
    def test_get_messages_multiple_calls(self):
        # Create an account with several messages and verify GetMessages clears them out gradually.
        username = "userC_reg"
        password_hash = "hashed"
        self.servicer.accounts[username] = {"password_hash": password_hash}
        self.servicer.messages[username] = []
        token = self.servicer._generate_session_token(username)
        
        # Insert 5 messages
        for i in range(5):
            msg = chat_pb2.Message(
                message_id=str(uuid.uuid4()),
                sender="sender_reg",
                recipient=username,
                content=f"Message {i}",
                timestamp=int(time.time()),
                read=False
            )
            self.servicer.messages[username].append(msg)
        
        # First call: retrieve 3 messages
        request1 = chat_pb2.GetMessagesRequest(
            username=username,
            limit=3,
            session_token=token
        )
        response1 = self.servicer.GetMessages(request1, self.context)
        self.assertEqual(len(response1.messages), 3)
        self.assertEqual(response1.remaining_messages, 2)
        
        # Second call: should retrieve the remaining 2 messages (if any)
        request2 = chat_pb2.GetMessagesRequest(
            username=username,
            limit=3,
            session_token=token
        )
        response2 = self.servicer.GetMessages(request2, self.context)
        self.assertEqual(len(response2.messages), 2)
    
    def test_logout_cleanup_regression(self):
        # Simulate a logout cleanup scenario where a user’s message queue is removed.
        username = "userD_reg"
        password_hash = "hashed"
        self.servicer.accounts[username] = {"password_hash": password_hash, "online": True}
        self.servicer.messages[username] = []
        
        # Simulate an online user with a dummy message queue
        dummy_queue = []
        self.servicer.online_users[username] = [dummy_queue]
        
        # Simulate the cleanup that happens in the ReceiveMessages finally clause:
        if username in self.servicer.online_users and dummy_queue in self.servicer.online_users[username]:
            self.servicer.online_users[username].remove(dummy_queue)
            if not self.servicer.online_users[username]:
                del self.servicer.online_users[username]
                self.servicer.accounts[username]["online"] = False
        
        self.assertNotIn(username, self.servicer.online_users)
        self.assertFalse(self.servicer.accounts[username]["online"])

if __name__ == '__main__':
    unittest.main()
