import sys
import grpc
import hashlib
import threading
import time
import logging
from typing import List, Optional
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget, QListWidgetItem,
                            QStackedWidget, QMessageBox, QInputDialog, QDialog, 
                            QFormLayout, QSpinBox, QDialogButtonBox, QTabWidget, QAbstractItemView)
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot, Qt
from PyQt5.QtGui import QPixmap, QPalette, QBrush

# Import the generated gRPC code
import chat_pb2
import chat_pb2_grpc
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('chat_client')

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

class MessageReceiver(QThread):
    """Thread for receiving messages from the server"""
    message_received = pyqtSignal(object)
    
    def __init__(self, config, username, session_token):
        super().__init__()
        self.config = config
        self.username = username
        self.session_token = session_token
        self.running = True
        
    def run(self):
        for server in self.config.server_list:
            print(server)
            try:
                channel = grpc.insecure_channel(server.client_address)
                stub = chat_pb2_grpc.ChatServiceStub(channel)
                request = chat_pb2.ReceiveMessagesRequest(
                    username=self.username,
                    session_token=self.session_token
                )
                
                for message in stub.ReceiveMessages(request):
                    if not self.running:
                        break
                    self.message_received.emit(message)
            except grpc.RpcError as e:
                print(f"gRPC Error in message receiver: {e}")
            except Exception as e:
                print(f"Error in message receiver: {e}")
        print("FUCK")
            
            
    def stop(self):
        self.running = False

class LoginDialog(QDialog):
    """Dialog for login or account creation"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setMinimumWidth(300)
        
        # Create layout
        layout = QVBoxLayout()
        
        # Login form
        form_layout = QFormLayout()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.login_button = QPushButton("Login")
        self.create_button = QPushButton("Create Account")
        
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.create_button)
        
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect signals
        self.login_button.clicked.connect(self.accept)
        self.create_button.clicked.connect(self.on_create_account)
        
        self.create_mode = False
        
    def on_create_account(self):
        self.create_mode = True
        self.accept()
        
    def get_credentials(self):
        return (
            self.username_input.text(),
            hash_password(self.password_input.text()),
            self.create_mode
        )

class MessageListItem(QListWidgetItem):
    """Custom list item to store message ID and display message info"""
    def __init__(self, message):
        display_text = f"From: {message.sender} - {time.ctime(message.timestamp)}\n{message.content[:50]}{'...' if len(message.content) > 50 else ''}"
        super().__init__(display_text)
        self.message_id = message.message_id
        self.setToolTip(message.content)

class ChatClient:
    def __init__(self, config: Config):
        self.config = config
        self.current_server = None
        self.stub = None
        self.session_token = None
        self.username = None
        self._connect_to_server()
        
    def _connect_to_server(self) -> bool:
        """Connect to an available server"""
        for server in self.config.server_list:
            try:
                channel = grpc.insecure_channel(server.client_address)
                stub = chat_pb2_grpc.ChatServiceStub(channel)
                # Try a simple request to check if server is responsive
                stub.ListAccounts(chat_pb2.ListAccountsRequest(
                    session_token="test",
                    pattern="",
                    page=1,
                    page_size=1
                ))
                self.current_server = server
                self.stub = stub
                logger.info(f"Connected to server at {server.client_address}")
                return True
            except grpc.RpcError as e:
                print(e)
                continue
        return False
        
    def _ensure_connection(self):
        """Ensure we have a working server connection"""
        if self.stub is None or self.current_server is None:
            if not self._connect_to_server():
                raise Exception("No available servers")
                
    def create_account(self, username: str, password: str) -> bool:
        """Create a new account"""
        self._ensure_connection()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            response = self.stub.CreateAccount(chat_pb2.CreateAccountRequest(
                username=username,
                password_hash=password_hash
            ))
            return response.success
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                # Try to reconnect and retry once
                if self._connect_to_server():
                    return self.create_account(username, password)
            raise
            
    def login(self, username: str, password: str) -> bool:
        """Login to an existing account"""
        self._ensure_connection()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            response = self.stub.Login(chat_pb2.LoginRequest(
                username=username,
                password_hash=password_hash
            ))
            if response.success:
                self.session_token = response.session_token
                self.username = username
            return response.success
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if self._connect_to_server():
                    return self.login(username, password)
            raise
            
    def list_accounts(self, pattern: str = "", page: int = 1) -> List[str]:
        """List all accounts matching the pattern"""
        self._ensure_connection()
        
        try:
            response = self.stub.ListAccounts(chat_pb2.ListAccountsRequest(
                session_token=self.session_token,
                pattern=pattern,
                page=page,
                page_size=50
            ))
            return response.usernames
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if self._connect_to_server():
                    return self.list_accounts(pattern, page)
            raise
            
    def delete_account(self, password: str) -> bool:
        """Delete the current account"""
        self._ensure_connection()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            response = self.stub.DeleteAccount(chat_pb2.DeleteAccountRequest(
                username=self.username,
                password_hash=password_hash,
                session_token=self.session_token
            ))
            if response.success:
                self.session_token = None
                self.username = None
            return response.success
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if self._connect_to_server():
                    return self.delete_account(password)
            raise
            
    def send_message(self, recipient: str, content: str) -> bool:
        """Send a message to another user"""
        self._ensure_connection()
        
        try:
            response = self.stub.SendMessage(chat_pb2.SendMessageRequest(
                sender=self.username,
                recipient=recipient,
                content=content,
                session_token=self.session_token
            ))
            return response.success
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if self._connect_to_server():
                    return self.send_message(recipient, content)
            raise
            
    def get_messages(self, limit: int = 100) -> List[chat_pb2.Message]:
        """Get messages for the current user"""
        self._ensure_connection()
        
        try:
            response = self.stub.GetMessages(chat_pb2.GetMessagesRequest(
                username=self.username,
                limit=limit,
                session_token=self.session_token
            ))
            return response.messages
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if self._connect_to_server():
                    return self.get_messages(limit)
            raise
            
    def delete_messages(self, message_ids: List[str]) -> bool:
        """Delete specific messages"""
        self._ensure_connection()
        
        try:
            response = self.stub.DeleteMessages(chat_pb2.DeleteMessagesRequest(
                message_ids=message_ids,
                session_token=self.session_token
            ))
            return response.success
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if self._connect_to_server():
                    return self.delete_messages(message_ids)
            raise
            
    def receive_messages(self, callback):
        """Start receiving messages in real-time"""
        self._ensure_connection()
        
        def message_stream():
            while True:
                try:
                    request = chat_pb2.ReceiveMessagesRequest(
                        username=self.username,
                        session_token=self.session_token
                    )
                    for message in self.stub.ReceiveMessages(request):
                        callback(message)
                except grpc.RpcError as e:
                    if e.code() == grpc.StatusCode.UNAVAILABLE:
                        logger.info("Lost connection to server, attempting to reconnect...")
                        if self._connect_to_server():
                            continue
                    logger.error(f"Error in message stream: {e}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in message stream: {e}")
                    break
                time.sleep(1)  # Wait before retrying
                
        thread = threading.Thread(target=message_stream, daemon=True)
        thread.start()
        return thread

class ChatWindow(QMainWindow):
    def __init__(self, config: Config):
        super().__init__()
        self.client = ChatClient(config)
        self.config = config
        self.message_receiver = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("gRPC Chat Client")
        self.resize(800, 600)
        
        # Set subway surfers background
        self.set_background()
        
        # Setup UI
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        main_layout = QVBoxLayout(self.central_widget)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        
        # Create login screen
        self.login_widget = QWidget()
        login_layout = QVBoxLayout(self.login_widget)
        
        server_layout = QHBoxLayout()
        server_layout.addWidget(QLabel("Server:"))
        self.server_input = QLineEdit("localhost:50051")
        server_layout.addWidget(self.server_input)
        self.connect_button = QPushButton("Connect")
        server_layout.addWidget(self.connect_button)
        
        login_layout.addLayout(server_layout)
        login_layout.addStretch()
        
        # Create main chat screen
        self.chat_widget = QWidget()
        chat_layout = QVBoxLayout(self.chat_widget)
        
        # User info
        user_info_layout = QHBoxLayout()
        self.user_label = QLabel("Not logged in")
        self.logout_button = QPushButton("Logout")
        user_info_layout.addWidget(self.user_label)
        user_info_layout.addStretch()
        user_info_layout.addWidget(self.logout_button)
        
        # Tab widget for chat features
        self.tabs = QTabWidget()
        
        # Messages tab
        self.messages_tab = QWidget()
        messages_layout = QVBoxLayout(self.messages_tab)
        
        # Message display section
        display_layout = QHBoxLayout()
        
        # Message list for selection
        self.message_list = QListWidget()
        self.message_list.setSelectionMode(QAbstractItemView.MultiSelection)
        
        # Message details
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)
        
        display_layout.addWidget(self.message_list, 1)
        display_layout.addWidget(self.message_display, 2)
        messages_layout.addLayout(display_layout)
        
        # Message actions
        message_actions_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Get Messages")
        self.message_count_input = QSpinBox()
        self.message_count_input.setMinimum(1)
        self.message_count_input.setMaximum(50)
        self.message_count_input.setValue(10)
        self.delete_selected_button = QPushButton("Delete Selected")
        self.delete_messages_button = QPushButton("Delete All")
        
        message_actions_layout.addWidget(self.refresh_button)
        message_actions_layout.addWidget(QLabel("Count:"))
        message_actions_layout.addWidget(self.message_count_input)
        message_actions_layout.addStretch()
        message_actions_layout.addWidget(self.delete_selected_button)
        message_actions_layout.addWidget(self.delete_messages_button)
        
        messages_layout.addLayout(message_actions_layout)
        
        # Send message tab
        self.send_tab = QWidget()
        send_layout = QVBoxLayout(self.send_tab)
        
        recipient_layout = QHBoxLayout()
        recipient_layout.addWidget(QLabel("To:"))
        self.recipient_input = QLineEdit()
        recipient_layout.addWidget(self.recipient_input)
        self.list_users_button = QPushButton("List Users")
        recipient_layout.addWidget(self.list_users_button)
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        
        send_button_layout = QHBoxLayout()
        send_button_layout.addStretch()
        self.send_button = QPushButton("Send")
        send_button_layout.addWidget(self.send_button)
        
        send_layout.addLayout(recipient_layout)
        send_layout.addWidget(self.message_input)
        send_layout.addLayout(send_button_layout)
        
        # User list tab
        self.users_tab = QWidget()
        users_layout = QVBoxLayout(self.users_tab)
        
        users_search_layout = QHBoxLayout()
        users_search_layout.addWidget(QLabel("Search:"))
        self.user_search_input = QLineEdit()
        users_search_layout.addWidget(self.user_search_input)
        self.search_button = QPushButton("Search")
        users_search_layout.addWidget(self.search_button)
        
        self.users_list = QListWidget()
        
        users_list_actions = QHBoxLayout()
        self.prev_page_button = QPushButton("Previous")
        self.page_label = QLabel("Page 1 of 1")
        self.next_page_button = QPushButton("Next")
        users_list_actions.addWidget(self.prev_page_button)
        users_list_actions.addWidget(self.page_label)
        users_list_actions.addWidget(self.next_page_button)
        
        users_layout.addLayout(users_search_layout)
        users_layout.addWidget(self.users_list)
        users_layout.addLayout(users_list_actions)
        
        # Account tab
        self.account_tab = QWidget()
        account_layout = QVBoxLayout(self.account_tab)
        
        self.delete_account_button = QPushButton("Delete Account")
        account_layout.addWidget(self.delete_account_button)
        account_layout.addStretch()
        
        # Add tabs
        self.tabs.addTab(self.messages_tab, "Messages")
        self.tabs.addTab(self.send_tab, "Send Message")
        self.tabs.addTab(self.users_tab, "User List")
        self.tabs.addTab(self.account_tab, "Account")
        
        # Add to main chat layout
        chat_layout.addLayout(user_info_layout)
        chat_layout.addWidget(self.tabs)
        
        # Add screens to stacked widget
        self.stacked_widget.addWidget(self.login_widget)
        self.stacked_widget.addWidget(self.chat_widget)
        
        main_layout.addWidget(self.stacked_widget)
        
        # Start with login screen
        self.stacked_widget.setCurrentWidget(self.login_widget)
        
        # Connect signals
        self.connect_button.clicked.connect(self.connect_to_server)
        self.logout_button.clicked.connect(self.logout)
        self.refresh_button.clicked.connect(self.get_messages)
        self.delete_selected_button.clicked.connect(self.delete_selected_messages)
        self.delete_messages_button.clicked.connect(self.delete_all_messages)
        self.send_button.clicked.connect(self.send_message)
        self.list_users_button.clicked.connect(self.show_users_tab)
        self.search_button.clicked.connect(self.search_users)
        self.prev_page_button.clicked.connect(self.previous_page)
        self.next_page_button.clicked.connect(self.next_page)
        self.delete_account_button.clicked.connect(self.delete_account)
        self.users_list.itemDoubleClicked.connect(self.select_user)
        self.message_list.itemClicked.connect(self.display_message_content)
        
        # State variables
        self.current_page = 1
        self.total_pages = 1
        self.user_messages = []
        self.messages_data = {}  # To store full message data
    
    def set_background(self):
        """Set a subway surfers background for the application"""
        try:
            # You would need to have a subway surfers background image file
            # This is a placeholder - replace with actual file path
            background_image = QPixmap("subway_surfers_bg.jpg")
            
            # If you don't have the file, you can use a gradient as fallback
            if background_image.isNull():
                palette = QPalette()
                palette.setColor(QPalette.Window, Qt.blue)
                self.setPalette(palette)
                print("Using fallback background color - place 'subway_surfers_bg.jpg' in app directory for image")
            else:
                palette = QPalette()
                palette.setBrush(QPalette.Window, QBrush(background_image.scaled(
                    self.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)))
                self.setPalette(palette)
        except Exception as e:
            print(f"Failed to set background: {e}")
        
    def connect_to_server(self):
        server_address = self.server_input.text()
        
        try:
            # Create gRPC channel
            self.channel = grpc.insecure_channel(server_address)
            self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)
            self.stub = self.client.stub
            
            # Show login dialog
            login_dialog = LoginDialog(self)
            result = login_dialog.exec_()
            
            if result == QDialog.Accepted:
                username, password_hash, create_mode = login_dialog.get_credentials()
                
                if create_mode:
                    self.create_account(username, password_hash)
                else:
                    self.login(username, password_hash)
                    
        except grpc.RpcError as e:
            QMessageBox.critical(self, "Connection Error", 
                                f"Failed to connect to server: {e}")
    
    def create_account(self, username, password_hash):
        """Create a new account by delegating to the client instance"""
        try:
            success = self.client.create_account(username, password_hash)
            if success:
                QMessageBox.information(self, "Success", "Account created successfully!")
                # Now login with the new account
                self.login(username, password_hash)
            else:
                QMessageBox.warning(self, "Error", "Failed to create account. Username may already exist.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error creating account: {e}")
    
    def login(self, username, password_hash):
        """Login to an existing account by delegating to the client instance"""
        try:
            success = self.client.login(username, password_hash)
            if success:
                self.username = username
                self.session_token = self.client.session_token
                
                # Update UI
                self.user_label.setText(f"Logged in as: {username}")
                self.stacked_widget.setCurrentWidget(self.chat_widget)
                
                # Start message receiver
                self.start_message_receiver()
                
                # Get existing messages
                self.get_messages()
            else:
                QMessageBox.warning(self, "Login Failed", "Invalid username or password")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during login: {e}")
            
    def start_message_receiver(self):
        # Stop existing receiver if any
        if self.message_receiver:
            self.message_receiver.stop()
            self.message_receiver.wait()
            
        # Start new receiver
        self.message_receiver = MessageReceiver(self.config, self.username, self.session_token)
        self.message_receiver.message_received.connect(self.handle_new_message)
        self.message_receiver.start()
        
    @pyqtSlot(object)
    def handle_new_message(self, message):
        """Handle a new message from the server"""
        # Add to message list
        item = MessageListItem(message)
        self.message_list.addItem(item)
        
        # Store full message data
        self.messages_data[message.message_id] = message
        
        # Also display in the text view
        self.message_display.append(
            f"<b>From: {message.sender}</b> <i>({time.ctime(message.timestamp)})</i><br>"
            f"{message.content}<br>"
            f"------------------------------<br>"
        )
        
    def display_message_content(self, item):
        """Display the selected message content in the detail view"""
        if isinstance(item, MessageListItem):
            message = self.messages_data.get(item.message_id)
            if message:
                self.message_display.clear()
                self.message_display.append(
                    f"<b>From: {message.sender}</b> <i>({time.ctime(message.timestamp)})</i><br>"
                    f"{message.content}<br>"
                )
        
    def logout(self):
        try:
            # Stop message receiver first to prevent any thread issues
            if self.message_receiver:
                self.message_receiver.stop()
                # Wait for the thread to finish but with a timeout
                if not self.message_receiver.wait(1000):  # 1 second timeout
                    print("Warning: Message receiver thread did not terminate cleanly")
                self.message_receiver = None
                
            # Clear session data
            self.username = None
            self.session_token = None
            
            # Clear UI
            self.message_display.clear()
            self.message_list.clear()
            self.message_input.clear()
            self.recipient_input.clear()
            self.users_list.clear()
            self.messages_data.clear()
            
            # Show login screen
            self.stacked_widget.setCurrentWidget(self.login_widget)
        except Exception as e:
            print(f"Error during logout: {e}")
            # Even if there's an error, try to reset the UI
            self.stacked_widget.setCurrentWidget(self.login_widget)
        
    def get_messages(self):
        if not self.session_token:
            QMessageBox.warning(self, "Not Logged In", "You must be logged in to get messages.")
            return
            
        try:
            # Use the client's get_messages method instead of accessing the stub directly
            messages = self.client.get_messages(self.message_count_input.value())
            
            # Clear previous messages
            self.user_messages = []
            self.message_list.clear()
            self.messages_data.clear()
            self.message_display.clear()
            
            # Display messages
            if messages:
                for message in messages:
                    # Add to message IDs list
                    self.user_messages.append(message.message_id)
                    
                    # Add to message list widget
                    item = MessageListItem(message)
                    self.message_list.addItem(item)
                    
                    # Store full message data
                    self.messages_data[message.message_id] = message
                
                QMessageBox.information(self, "Messages Retrieved", 
                                      f"Retrieved {len(messages)} messages.")
            else:
                QMessageBox.information(self, "No Messages", "You have no messages.")
                
        except grpc.RpcError as e:
            QMessageBox.critical(self, "Error", f"Failed to get messages: {e}")
    
    def delete_selected_messages(self):
        """Delete only the selected messages"""
        selected_items = self.message_list.selectedItems()
        
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select messages to delete.")
            return
        
        message_ids = [item.message_id for item in selected_items]
        
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                     f"Are you sure you want to delete {len(message_ids)} selected messages?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                                     
        if reply == QMessageBox.Yes:
            try:
                # Use the client's delete_messages method instead of accessing the stub directly
                success = self.client.delete_messages(message_ids)
                
                if success:
                    # Fix: Use length of selected items to show the correct count
                    QMessageBox.information(self, "Success", 
                                          f"Deleted {len(message_ids)} messages.")
                    
                    # Remove deleted messages from UI and data structures
                    for item in selected_items:
                        msg_id = item.message_id
                        row = self.message_list.row(item)
                        self.message_list.takeItem(row)
                        if msg_id in self.messages_data:
                            del self.messages_data[msg_id]
                        if msg_id in self.user_messages:
                            self.user_messages.remove(msg_id)
                    
                    self.message_display.clear()
                else:
                    QMessageBox.warning(self, "Deletion Failed", "Failed to delete messages.")
                    
            except grpc.RpcError as e:
                QMessageBox.critical(self, "Error", f"Failed to delete messages: {e}")
            
    def delete_all_messages(self):
        if not self.user_messages:
            QMessageBox.information(self, "No Messages", "No messages to delete.")
            return
            
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                     "Are you sure you want to delete all messages?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                                     
        if reply == QMessageBox.Yes:
            try:
                # Use the client's delete_messages method instead of accessing the stub directly
                success = self.client.delete_messages(self.user_messages)
                
                if success:
                    QMessageBox.information(self, "Success", 
                                          f"Deleted {len(self.user_messages)} messages.")
                    self.message_display.clear()
                    self.message_list.clear()
                    self.user_messages = []
                    self.messages_data.clear()
                else:
                    QMessageBox.warning(self, "Deletion Failed", response.message)
                    
            except grpc.RpcError as e:
                QMessageBox.critical(self, "Error", f"Failed to delete messages: {e}")
                
    def send_message(self):
        recipient = self.recipient_input.text()
        content = self.message_input.toPlainText()
        
        if not recipient or not content:
            QMessageBox.warning(self, "Invalid Input", "Please enter a recipient and message content.")
            return
            
        try:
            # Use the client's send_message method instead of accessing the stub directly
            success = self.client.send_message(recipient, content)
            
            if success:
                QMessageBox.information(self, "Success", "Message sent successfully.")
                self.message_input.clear()
            else:
                QMessageBox.warning(self, "Send Failed", "Failed to send message.")
                
        except grpc.RpcError as e:
            QMessageBox.critical(self, "Error", f"Failed to send message: {e}")
            
    def show_users_tab(self):
        self.tabs.setCurrentWidget(self.users_tab)
        self.search_users()
        
    def search_users(self):
        pattern = self.user_search_input.text()
        
        try:
            # Use the client's list_accounts method instead of accessing the stub directly
            usernames = self.client.list_accounts(pattern, self.current_page)
            
            # Since we're not getting pagination info directly anymore, we'll simplify pagination
            # In a real app, you'd want to handle pagination properly based on server response
            self.total_pages = max(1, len(usernames) // 10 + (1 if len(usernames) % 10 > 0 else 0))
            self.page_label.setText(f"Page {self.current_page} of {self.total_pages}")
            
            # Enable/disable pagination buttons
            self.prev_page_button.setEnabled(self.current_page > 1)
            self.next_page_button.setEnabled(self.current_page < self.total_pages)
            
            # Display users
            self.users_list.clear()
            for username in usernames:
                self.users_list.addItem(username)
                
        except grpc.RpcError as e:
            QMessageBox.critical(self, "Error", f"Failed to list users: {e}")
            
    def previous_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.search_users()
            
    def next_page(self):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.search_users()
            
    def select_user(self, item):
        self.recipient_input.setText(item.text())
        self.tabs.setCurrentWidget(self.send_tab)
        
    def delete_account(self):
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                 "Are you sure you want to delete your account? This cannot be undone.",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                                 
        if reply == QMessageBox.Yes:
            # Ask for password confirmation
            password, ok = QInputDialog.getText(self, "Password Confirmation", 
                                             "Enter your password to confirm:", 
                                             QLineEdit.Password)
                                             
            if ok and password:
                try:
                    # Use the client's delete_account method instead of accessing the stub directly
                    success = self.client.delete_account(password)
                    
                    if success:
                        QMessageBox.information(self, "Success", "Account deleted successfully.")
                        self.logout()
                    else:
                        QMessageBox.warning(self, "Deletion Failed", "Failed to delete account.")
                        
                except grpc.RpcError as e:
                    QMessageBox.critical(self, "Error", f"Failed to delete account: {e}")

    # Override resize event to maintain background when window is resized
    def resizeEvent(self, event):
        self.set_background()
        super().resizeEvent(event)

def main():
    app = QApplication(sys.argv)
    
    # Load configuration
    config = Config(3)
    if len(sys.argv) > 1:
        # TODO: Load config from file
        pass
        
    window = ChatWindow(config)
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()