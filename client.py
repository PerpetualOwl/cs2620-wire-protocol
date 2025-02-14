import socket
import threading
import sys
from typing import Any, Optional, Union, Callable
from utils import *
import time
import json
import uuid
import subprocess
from threading import Thread

from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTextBrowser, QLineEdit, QPushButton,
                             QInputDialog, QMessageBox, QLabel, QComboBox, 
                             QListWidget, QAbstractItemView, QListWidgetItem,
                             QCompleter)

SERVER_PUBLIC_KEY: Optional[bytes] = None

chat_data = ChatData()
username = None
password = None
logged_in = False
login_failed = False

chat_window = None

def print_thread(text: str) -> None:
    print("\033[F", end="", flush=True)  # Move cursor up one line
    print("\033[K", end="", flush=True)  # Clear the current line
    print(text, flush=True)
    print("\033[E", end="", flush=True)  # Move cursor to the beginning of the next line

def process_server_message_gui(data: bytes) -> None:
    """
    Process server messages for the GUI.
    Now also handles the UNREAD_MESSAGES_RESPONSE which contains unread messages.
    """
    global chat_window, chat_data, SERVER_PUBLIC_KEY
    try:
        packet: ServerPacket = deserialize_packet(data, ServerPacket)
        if packet.type == MessageType.PUBLIC_KEY_RESPONSE:
            SERVER_PUBLIC_KEY = packet.data["public_key"].encode("utf-8")
            print("Received server public key.")
        elif packet.type == MessageType.CREATE_USER_RESPONSE:
            # Forward the login response to the chat window:
            if chat_window:
                chat_window.handle_login_response(packet.data)
        elif packet.type == MessageType.MESSAGE_RECEIVED:
            message_data = packet.data
            try:
                new_msg = ChatMessage(**message_data)
                chat_data.add_message(new_msg)
            except Exception as e:
                print("Error adding message:", e)
        elif packet.type == MessageType.UNREAD_MESSAGES_RESPONSE:
            # New branch: Process a list of unread messages sent by the server.
            messages_list = packet.data.get("messages", [])
            if not isinstance(messages_list, list):
                print("Unexpected unread messages format.")
            else:
                for msg_data in messages_list:
                    try:
                        new_msg = ChatMessage(**msg_data)
                        chat_data.add_message(new_msg)
                    except Exception as e:
                        print("Error adding unread message:", e)
                print(f"Added {len(messages_list)} unread message(s).")
        elif packet.type == MessageType.MESSAGE_DELETED:
            message_id = packet.data["message_id"]
            # Delete message (adjusting the call since our ChatData.delete_message requires sender info only for backend)
            chat_data.delete_message("", message_id)
        elif packet.type == MessageType.USER_ADDED:
            uname = packet.data["username"]
            chat_data.add_user(uname)
        elif packet.type == MessageType.USER_DELETED:
            uname = packet.data["username"]
            chat_data.delete_user(uname)
        elif packet.type == MessageType.INITIAL_CHATDATA:
            messages = packet.data["messages"]
            chat_data = ChatData(**messages)
        # (Other packet types can be handled as needed.)
    except Exception as e:
        print("Error processing server message (GUI):", e)

def send_packet_to_server(packet: ClientPacket) -> None:
    """Sends a packet to the server."""
    global SERVER_PUBLIC_KEY, client_socket
    try:
        if SERVER_PUBLIC_KEY is not None:
            data: bytes = encrypt(SERVER_PUBLIC_KEY, serialize_packet(packet))
        elif packet.type == MessageType.REQUEST_PUBLIC_KEY:
            data: bytes = serialize_packet(packet)
        else:
            print_thread("Server public key not available. Cannot send packet.")
            return
        client_socket.sendall(data)
    except Exception as e:
        print_thread(f"Error sending packet: {e}")
        sys.exit(1)

def on_startup() -> None:
    """Function that runs on client startup."""
    try:
        send_packet_to_server(ServerPacket(type=MessageType.REQUEST_PUBLIC_KEY))
    except Exception as e:
        print(f"Error on startup: {e}")
        sys.exit(1)

# Define our main chat window.
class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = None
        self.password = None  # this will be the hashed password
        self.logged_in = False

        self.setWindowTitle("Chat Client")
        self.resize(600, 500)

        # Main central widget and layout.
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Chat display section.
        self.chat_display = QTextBrowser(self)
        self.chat_display.setReadOnly(True)
        main_layout.addWidget(QLabel("Chat Messages:"))
        main_layout.addWidget(self.chat_display)

        # Available Users section.
        self.available_users = []
        users_layout = QHBoxLayout()
        self.users_label = QLabel("Available Users:")
        users_layout.addWidget(self.users_label)
        self.users_combobox = QComboBox(self)
        self.users_combobox.setEditable(True)                                    # <-- allow typing
        # Create and set the completer with case-insensitive substring matching:
        self.userCompleter = QCompleter([], self)
        self.userCompleter.setCaseSensitivity(Qt.CaseInsensitive)
        self.userCompleter.setFilterMode(Qt.MatchContains)
        self.users_combobox.setCompleter(self.userCompleter)
        users_layout.addWidget(self.users_combobox)
        main_layout.addLayout(users_layout)
        self.users_combobox.activated[str].connect(self.on_user_selected)


        # Layout for sending messages.
        send_layout = QHBoxLayout()
        self.recipient_edit = QLineEdit(self)
        self.recipient_edit.setPlaceholderText("Recipient username")
        send_layout.addWidget(self.recipient_edit)
        self.message_edit = QLineEdit(self)
        self.message_edit.setPlaceholderText("Type your message here...")
        send_layout.addWidget(self.message_edit)
        self.send_button = QPushButton("Send", self)
        send_layout.addWidget(self.send_button)
        main_layout.addLayout(send_layout)
        self.send_button.clicked.connect(self.on_send_message)
        self.message_edit.returnPressed.connect(self.on_send_message)

        # Layout for message deletion controls.
        deletion_layout = QHBoxLayout()
        deletion_layout.addWidget(QLabel("Your Messages:"))

        # Instead of a dropdown, create a list widget that allows multi-selection:
        self.message_list = QListWidget(self)
        self.message_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        deletion_layout.addWidget(self.message_list)

        self.delete_message_button = QPushButton("Delete Selected Message", self)
        deletion_layout.addWidget(self.delete_message_button)
        main_layout.addLayout(deletion_layout)
        self.delete_message_button.clicked.connect(self.on_delete_message)

        # Layout for account deletion.
        account_deletion_layout = QHBoxLayout()
        self.delete_account_button = QPushButton("Delete Account", self)
        account_deletion_layout.addWidget(self.delete_account_button)
        main_layout.addLayout(account_deletion_layout)
        self.delete_account_button.clicked.connect(self.on_delete_account)

        # ***** New: Layout for requesting unread messages *****
        unread_layout = QHBoxLayout()
        unread_layout.addWidget(QLabel("Unread Count:"))
        self.unread_count_edit = QLineEdit(self)
        self.unread_count_edit.setPlaceholderText("Enter number")
        unread_layout.addWidget(self.unread_count_edit)
        self.request_unread_button = QPushButton("Request Unread Messages", self)
        unread_layout.addWidget(self.request_unread_button)
        main_layout.addLayout(unread_layout)
        self.request_unread_button.clicked.connect(self.on_request_unread_messages)
        # *********************************************************

        # Timer to periodically update the chat display, available users, and message dropdown.
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_chat_display)
        self.update_timer.start(500)  # update every 500ms

        # Prompt for login/registration shortly after startup.
        QTimer.singleShot(100, self.login)

    def login(self):
        """Prompt for username and password then send login/create packet."""
        username, ok = QInputDialog.getText(self, "Login / Register", "Username:")
        if not ok or not username.strip():
            self.close()
            return
        self.username = username.strip()

        password, ok = QInputDialog.getText(self, "Login / Register", "Password:", QLineEdit.Password)
        if not ok or not password:
            self.close()
            return
        # Immediately hash the password.
        self.password = hash_password(password)
        # Build and send the login/create packet.
        packet = ClientPacket(
            type=MessageType.CREATE_USER_REQUEST,
            data={"username": self.username, "password": self.password}
        )
        send_packet_to_server(packet)
        self.statusBar().showMessage("Login/Registration attempt sent. Waiting for server response...")

    @pyqtSlot()
    def on_send_message(self):
        """Send a message packet when the user hits the Send button or presses Enter."""
        if not self.logged_in:
            QMessageBox.warning(self, "Not logged in", "Please log in first.")
            return

        recipient = self.recipient_edit.text().strip()
        if not recipient:
            QMessageBox.warning(self, "Missing recipient", "Please enter or select a recipient.")
            return

        text = self.message_edit.text().strip()
        if not text:
            return

        packet = ClientPacket(
            type=MessageType.SEND_MESSAGE,
            data={"sender": self.username, "recipient": recipient, "message": text, "password": self.password}
        )
        send_packet_to_server(packet)
        self.message_edit.clear()
    
    @pyqtSlot()
    def on_delete_message(self):
        if not self.logged_in:
            QMessageBox.warning(self, "Not logged in", "Please log in first.")
            return
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "No messages selected for deletion.")
            return
        # Gather message IDs from the selected items.
        message_ids = [item.data(Qt.UserRole) for item in self.message_list.selectedItems()]
        packet = ClientPacket(
            type=MessageType.DELETE_MESSAGES,
            data={"username": self.username, "message_ids": message_ids, "password": self.password}
        )
        send_packet_to_server(packet)

    @pyqtSlot()
    def on_delete_account(self):
        """Ask for confirmation then send a DELETE_ACCOUNT packet."""
        reply = QMessageBox.question(
            self,
            "Delete Account",
            "Are you sure you want to delete your account? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            packet = ClientPacket(
                type=MessageType.DELETE_ACCOUNT,
                data={"username": self.username, "password": self.password}
            )
            send_packet_to_server(packet)
            QMessageBox.information(self, "Account Deleted",
                                    "Your account has been deleted. The application will now close.")
            self.close()

    @pyqtSlot()
    def on_request_unread_messages(self):
        """Send a packet to request unread messages from the server."""
        if not self.logged_in:
            QMessageBox.warning(self, "Not logged in", "Please log in first.")
            return
        count_text = self.unread_count_edit.text().strip()
        if not count_text.isdigit():
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid number for unread message count.")
            return
        packet = ClientPacket(
            type=MessageType.REQUEST_UNREAD_MESSAGES,
            data={"username": self.username, "num_messages": count_text, "password": self.password}
        )
        send_packet_to_server(packet)
        self.unread_count_edit.clear()
        self.statusBar().showMessage(f"Requested {count_text} unread messages...", 3000)

    def update_chat_display(self):
        """
        Refresh the chat display, update the available users list,
        and update the dropdown listing of your own messages.
        """
        selected_message_ids = set(
            item.data(Qt.UserRole) for item in self.message_list.selectedItems()
        )

        self.chat_display.clear()
        self.message_list.clear()
        user_messages = []

        try:
            messages_list = list(chat_data.messages.values())
            messages_list.sort(key=lambda m: m.timestamp)
            for msg in messages_list:
                tstamp = msg.timestamp.strftime("%H:%M:%S") if not isinstance(msg.timestamp, str) else msg.timestamp
                html_line = f'<span title="Message ID: {msg.message_id}">[{tstamp}] {msg.sender} → {msg.recipient}: {msg.message}</span>'
                self.chat_display.append(html_line)
                if msg.sender == self.username:
                    user_messages.append(msg)
        except Exception as e:
            print(f"Error updating chat display: {e}")

        for msg in user_messages:
            tstamp = msg.timestamp.strftime("%H:%M:%S") if not isinstance(msg.timestamp, str) else msg.timestamp
            preview = msg.message if len(msg.message) <= 20 else msg.message[:20] + "..."
            display_text = f"[{tstamp}] {preview}"
            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, msg.message_id)
            self.message_list.addItem(item)

            if msg.message_id in selected_message_ids:
                item.setSelected(True)

        if self.username:
            available_users = sorted(user for user in chat_data.users if user != self.username)
        else:
            available_users = sorted(list(chat_data.users))

        if available_users != self.available_users:
            self.available_users = available_users
            self.users_combobox.clear()
            
            self.users_combobox.addItems(self.available_users)
            self.userCompleter.model().setStringList(self.available_users)

    @pyqtSlot(str)
    def on_user_selected(self, selected_user: str):
        """When a user is selected, copy that name into the recipient field."""
        self.recipient_edit.setText(selected_user)

    @pyqtSlot(dict)
    def handle_login_response(self, response):
        """
        This slot is intended to be called when a CREATE_USER_RESPONSE is received.
        The 'response' dictionary should include "success" and "message".
        """
        if response.get("success"):
            if response.get("success"):
                self.logged_in = True
                # Use the server’s message that now contains the unread count.
                self.statusBar().showMessage(response.get("message", f"Logged in successfully! Welcome, {self.username}!"))
            # Once logged in, optionally request initial messages.
            packet = ClientPacket(
                type=MessageType.REQUEST_MESSAGES,
                data={"sender": self.username, "password": self.password}
            )
            send_packet_to_server(packet)
        else:
            QMessageBox.critical(self, "Login Failed", response.get("message", "Unknown error"))
            QApplication.quit()
            subprocess.Popen([sys.executable] + sys.argv)

def receive_data():
    """Receive data from the server in a loop."""
    global client_socket
    while True:
        try:
            data: bytes = client_socket.recv(65536)
            if not data:
                print("Server disconnected.")
                break
            process_server_message_gui(data)
        except Exception as e:
            print("Error receiving data:", e)
            break
    client_socket.close()
    sys.exit(0)

def start_gui():
    """Creates the QApplication and ChatWindow; then starts the event loop."""
    global chat_window
    app = QApplication(sys.argv)
    chat_window = ChatWindow()
    chat_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    # Create the client socket and connect.
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")
    except Exception as e:
        print("Connection error:", e)
        sys.exit(1)

    # Start a thread to listen for server messages.
    receive_thread = Thread(target=receive_data, daemon=True)
    receive_thread.start()

    # Request the server public key and then start the GUI.
    on_startup()
    start_gui()