import socket
import threading
import sys
from typing import Any, Optional, Union, Callable
from utils import *
import time
import json
import uuid
from threading import Thread

from PyQt5.QtCore import QTimer, pyqtSlot
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTextBrowser, QLineEdit, QPushButton,
                             QInputDialog, QMessageBox, QLabel, QComboBox)

SERVER_PUBLIC_KEY: Optional[bytes] = None

chat_data = ChatData()
username = None
password = None
logged_in = False
login_failed = False

chat_window = None

def print_thread(text: str) -> None:
    print("\033[F", end="", flush=True)  # Move cursor up one line
    print("\033[K", end="", flush=True) # Clear the current line
    print(text, flush=True)
    print("\033[E", end="", flush=True) # Move cursor to the beginning of the next line


def process_server_message(data: bytes) -> None:
    """Processes data received from the server."""
    global SERVER_PUBLIC_KEY, chat_data, logged_in, login_failed
    try:
        packet: ServerPacket = deserialize_packet(data, ServerPacket)
        match packet.type:
            case MessageType.PUBLIC_KEY_RESPONSE:
                SERVER_PUBLIC_KEY = packet.data["public_key"].encode("utf-8")
                print_thread("Received server public key.")
            case MessageType.MESSAGE_RECEIVED:
                message_data = packet.data
                message = ChatMessage(**message_data)  # Create ChatMessage object
                chat_data.add_message(message)
                print_thread(f"New message received from {message.sender}: {message.message}")
            case MessageType.MESSAGE_DELETED:
                message_id = packet.data["message_id"]
                chat_data.delete_message(message_id)
                print_thread(f"Message deleted: {message_id}")
            case MessageType.USER_ADDED:
                username = packet.data["username"]
                chat_data.add_user(username)
                print_thread(f"User added: {username}")
            case MessageType.USER_DELETED:
                username = packet.data["username"]
                chat_data.delete_user(username)
                print_thread(f"User deleted: {username}")
            case MessageType.CREATE_USER_RESPONSE:
                logged_in = packet.data["success"]
                message = packet.data["message"]
                if logged_in:
                    print_thread(f"User created/login successful: {message}")
                else:
                    login_failed = True
                    print_thread(f"Failed to create user: {message}")
            case MessageType.ALL_MESSAGES:
                messages = packet.data["messages"]
                chat_data = ChatData(**messages)
                print_thread("All messages loaded.")
                print_thread(chat_data)
            case _:
                print_thread(f"Received unknown message type: {packet.type}")
    except Exception as e:
        print_thread(f"Error processing server message: {e}")

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


def handle_user_input() -> None:
    """Handles user input, now with commands."""
    global username, password, logged_in, login_failed
    time.sleep(1)
    while (username is None or password is None) and not logged_in:  # Force login/registration
        username = input("Username: ")
        password = input("Password: ")

        # hash password immediately, and discard the original
        password = hash_password(password)

        packet = ClientPacket(type=MessageType.CREATE_USER_REQUEST, data={"username": username, "password": password})
        send_packet_to_server(packet)
        print_thread("Login/Registration attempt sent. Waiting for server response...")
        while not logged_in and not login_failed:
            pass
        if login_failed:
            print_thread("Login/Registration failed. Try again.")
            username = None
            password = None
            logged_in = False
            login_failed = False
        else:
            print_thread("Logged in successfully.")
            break

    # load all messages
    packet = ClientPacket(type=MessageType.REQUEST_MESSAGES, data = {"sender": username, "password": password})
    send_packet_to_server(packet)

    while True:
        try:
            user_input: str = input("> ")
            parts = user_input.split()
            command = parts[0]

            if command == "send":
                if len(parts) < 3:
                    print_thread("Usage: send <recipient> <message>")
                else:
                    recipient = parts[1]
                    message = " ".join(parts[2:])  # Join the rest as the message
                    packet = ClientPacket(type=MessageType.SEND_MESSAGE, data={"sender": username, "recipient": recipient, "message": message, "password": password})
                    send_packet_to_server(packet)
            elif command == "delete":
                if len(parts) != 2:
                    print_thread("Usage: delete <message_id>")
                else:
                    message_id = parts[1]
                    packet = ClientPacket(type=MessageType.DELETE_MESSAGE, data={"username": username, "message_id": message_id, "password": password})
                    send_packet_to_server(packet)
            elif command == "delete_account":
                packet = ClientPacket(type=MessageType.DELETE_ACCOUNT, data={"username": username, "password": password})
                send_packet_to_server(packet)
                print_thread("Account deleted.")
                break
            elif command == "request_messages":
                packet = ClientPacket(type=MessageType.REQUEST_MESSAGES, data = {"sender": username, "password": password})
                send_packet_to_server(packet)
            elif command == "exit":
                break # Exit the loop and close the connection
            else:
                print_thread("Invalid command.")

        except EOFError:
            print_thread("EOF (Ctrl+D) received. Exiting.")
            break
        except Exception as e:
            print_thread(f"Error processing input: {e}")
            break

    client_socket.close()
    sys.exit(0)

def receive_data() -> None:
    """Receives data from the server in a loop."""
    while True:
        try:
            data: bytes = client_socket.recv(1024)
            if not data:  # Server disconnected
                print_thread("Server disconnected.")
                break
            process_server_message(data)
        except OSError as e:
            print_thread(f"Socket error: {e}")
            break
        except Exception as e:
            print_thread(f"Error receiving data: {e}")
            break
    client_socket.close()
    raise SystemExit(0)


def on_startup() -> None:
    """Function that runs on client startup."""
    try:
        send_packet_to_server(ServerPacket(type=MessageType.REQUEST_PUBLIC_KEY))
    except Exception as e:
        print(f"Error on startup: {e}")
        sys.exit(1)

# Define a QMainWindow subclass that will serve as our chat client GUI.
class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = None
        self.password = None  # this will be the hashed password
        self.logged_in = False

        self.setWindowTitle("Chat Client")
        self.resize(600, 400)

        # Main central widget and layout.
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Chat display (we use HTML so that each text line has a tooltip with its message_id).
        self.chat_display = QTextBrowser(self)
        self.chat_display.setReadOnly(True)
        main_layout.addWidget(QLabel("Chat Messages:"))
        main_layout.addWidget(self.chat_display)

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
        
        # Layout for message deletion controls with a dropdown.
        deletion_layout = QHBoxLayout()
        deletion_layout.addWidget(QLabel("Your Messages:"))
        self.message_dropdown = QComboBox(self)
        deletion_layout.addWidget(self.message_dropdown)
        self.delete_message_button = QPushButton("Delete Selected Message", self)
        deletion_layout.addWidget(self.delete_message_button)
        main_layout.addLayout(deletion_layout)
        
        # Layout for account deletion.
        account_deletion_layout = QHBoxLayout()
        self.delete_account_button = QPushButton("Delete Account", self)
        account_deletion_layout.addWidget(self.delete_account_button)
        main_layout.addLayout(account_deletion_layout)

        # Connect signals.
        self.send_button.clicked.connect(self.on_send_message)
        self.message_edit.returnPressed.connect(self.on_send_message)
        self.delete_message_button.clicked.connect(self.on_delete_message)
        self.delete_account_button.clicked.connect(self.on_delete_account)

        # Timer to periodically update the chat display and your message dropdown.
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_chat_display)
        self.update_timer.start(500)  # update every 500 ms

        # Prompt for login/registration shortly after startup.
        QTimer.singleShot(100, self.login)

    def login(self):
        """Prompt the user for username and password, then send login/create packet."""
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
            QMessageBox.warning(self, "Missing recipient", "Please enter a recipient.")
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
        """Delete the message selected from the dropdown list."""
        if not self.logged_in:
            QMessageBox.warning(self, "Not logged in", "Please log in first.")
            return
        # Get the message_id stored as the item data from the currently selected dropdown entry.
        message_id = self.message_dropdown.currentData()
        if message_id is None:
            QMessageBox.information(self, "No Selection", "No message selected for deletion.")
            return

        # Send a DELETE_MESSAGE packet.
        packet = ClientPacket(
            type=MessageType.DELETE_MESSAGE,
            data={"username": self.username, "message_id": message_id, "password": self.password}
        )
        send_packet_to_server(packet)

    @pyqtSlot()
    def on_delete_account(self):
        """Ask for confirmation then send a DELETE_ACCOUNT packet to the server."""
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
            QMessageBox.information(self, "Account Deleted", "Your account has been deleted. The application will now close.")
            self.close()

    def update_chat_display(self):
        """Refresh the chat display and update the dropdown listing of your own message IDs.
        
        Each message is added as an HTML element so that the message_id appears as a tooltip (on hover).
        The dropdown is populated only with messages sent by you, with each item’s userData set to the corresponding message_id.
        """
        self.chat_display.clear()
        # Reset the dropdown.
        self.message_dropdown.clear()
        # We'll collect messages you sent (for deletion) separately.
        user_messages = []

        try:
            messages = list(chat_data.messages.values())
            messages.sort(key=lambda m: m.timestamp)
            for msg in messages:
                # Create HTML that shows message details and uses the message_id as a tooltip.
                tstamp = msg.timestamp.strftime("%H:%M:%S") if not isinstance(msg.timestamp, str) else msg.timestamp
                html_line = f'<span title="Message ID: {msg.message_id}">[{tstamp}] {msg.sender} → {msg.recipient}: {msg.message}</span>'
                self.chat_display.append(html_line)
                if msg.sender == self.username:
                    user_messages.append(msg)
        except Exception as e:
            print(f"Error updating chat display: {e}")

        # Populate the dropdown with a short summary for each of your messages.
        for msg in user_messages:
            tstamp = msg.timestamp.strftime("%H:%M:%S") if not isinstance(msg.timestamp, str) else msg.timestamp
            preview = msg.message if len(msg.message) <= 20 else msg.message[:20] + "..."
            display_text = f"[{tstamp}] {preview}"
            # Use addItem(display, userData) so that when selected you get the message_id.
            self.message_dropdown.addItem(display_text, msg.message_id)

    @pyqtSlot(dict)
    def handle_login_response(self, response):
        """
        This slot is intended to be called (via a thread‐safe signal) when a CREATE_USER_RESPONSE is received.
        The 'response' parameter should be a dict with keys "success" and "message".
        """
        if response.get("success"):
            self.logged_in = True
            self.statusBar().showMessage("Logged in successfully!")
            # Once logged in, request all messages.
            packet = ClientPacket(
                type=MessageType.REQUEST_MESSAGES,
                data={"sender": self.username, "password": self.password}
            )
            send_packet_to_server(packet)
        else:
            QMessageBox.warning(self, "Login Failed", response.get("message", "Unknown error"))
            # Prompt for login credentials again.
            self.login()

# To integrate our new GUI‐based input with the rest of the client, we modify process_server_message() so that,
# whenever a CREATE_USER_RESPONSE is received the chat window is updated. For example, modify process_server_message() as follows:
def process_server_message_gui(data: bytes) -> None:
    """
    This function is similar to your original process_server_message() but (a) it avoids printing
    to the console and (b) it forwards login responses and message updates to the GUI.
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
                # Since this slot runs on the main thread we can invoke the slot safely.
                chat_window.handle_login_response(packet.data)
        elif packet.type == MessageType.MESSAGE_RECEIVED:
            message_data = packet.data
            # Create a ChatMessage object and add it to chat_data.
            try:
                new_msg = ChatMessage(**message_data)
                chat_data.add_message(new_msg)
            except Exception as e:
                print("Error adding message:", e)
        elif packet.type == MessageType.MESSAGE_DELETED:
            message_id = packet.data["message_id"]
            chat_data.delete_message("", message_id)  # adjust as needed
        elif packet.type == MessageType.USER_ADDED:
            username = packet.data["username"]
            chat_data.add_user(username)
        elif packet.type == MessageType.USER_DELETED:
            username = packet.data["username"]
            chat_data.delete_user(username)
        elif packet.type == MessageType.ALL_MESSAGES:
            # Replace chat_data.messages from the packet data.
            messages = packet.data["messages"]
            chat_data = ChatData(**messages)
        # (Other packet types can be handled as you see fit.)
    except Exception as e:
        print("Error processing server message (GUI):", e)


# In the receive_data() thread function, replace the call to process_server_message() with process_server_message_gui()
def receive_data():
    """Receives data from the server in a loop."""
    global client_socket
    while True:
        try:
            data: bytes = client_socket.recv(1024)
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
    """This function creates the QApplication and ChatWindow and starts the GUI event loop."""
    global chat_window
    app = QApplication(sys.argv)
    chat_window = ChatWindow()
    chat_window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    import socket
    # Create your client socket as before:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")
    except Exception as e:
        print("Connection error:", e)
        sys.exit(1)

    # Start a thread to listen from the server:
    receive_thread = Thread(target=receive_data, daemon=True)
    receive_thread.start()

    # Launch the Qt GUI (which replaces the old handle_user_input() loop).
    on_startup()
    start_gui()

"""
if __name__ == "__main__":
    client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")

        receive_thread: threading.Thread = threading.Thread(target=receive_data)
        user_thread: threading.Thread = threading.Thread(target=handle_user_input)

        receive_thread.daemon = True
        user_thread.daemon = True

        receive_thread.start()
        user_thread.start()

        on_startup()

        while True:
            pass

    except ConnectionRefusedError:
        print(f"Connection to {SERVER_IP}:{SERVER_PORT} refused. Make sure the server is running.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
"""