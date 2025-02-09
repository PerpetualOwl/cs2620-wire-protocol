import socket
import threading
import sys
from typing import Any, Optional, Union, Callable
from utils import *
import time

SERVER_PUBLIC_KEY: Optional[bytes] = None

chat_data = ChatData()
username = None
password = None
logged_in = False
login_failed = False

def process_server_message(data: bytes) -> None:
    """Processes data received from the server."""
    global SERVER_PUBLIC_KEY, chat_data, logged_in, login_failed
    try:
        packet: ServerPacket = deserialize_packet(data, ServerPacket)
        match packet.type:
            case MessageType.PUBLIC_KEY_RESPONSE:
                SERVER_PUBLIC_KEY = packet.data["public_key"].encode("utf-8")
                print("Received server public key.")
            case MessageType.MESSAGE_RECEIVED:
                message_data = packet.data
                message = ChatMessage(**message_data)  # Create ChatMessage object
                chat_data.add_message(message)
                print(f"New message received from {message.sender}: {message.message}")
            case MessageType.MESSAGE_DELETED:
                message_id = packet.data["message_id"]
                chat_data.delete_message(message_id)
                print(f"Message deleted: {message_id}")
            case MessageType.USER_DELETED:
                username = packet.data["username"]
                chat_data.delete_user(username)
                print(f"User deleted: {username}")
            case MessageType.CREATE_USER_RESPONSE:
                logged_in = packet.data["success"]
                message = packet.data["message"]
                if logged_in:
                    print(f"User created/login successful: {message}")
                else:
                    login_failed = True
                    print(f"Failed to create user: {message}")
            case _:
                print(f"Received unknown message type: {packet.type}")
    except Exception as e:
        print(f"Error processing server message: {e}")

def send_packet_to_server(packet: ClientPacket) -> None:
    """Sends a packet to the server."""
    try:
        if SERVER_PUBLIC_KEY is not None:
            # data: bytes = encrypt(serialize_packet(packet), SERVER_PUBLIC_KEY)
            data: bytes = serialize_packet(packet)
        elif packet.type == MessageType.REQUEST_PUBLIC_KEY:
            data: bytes = serialize_packet(packet)
        else:
            print("Server public key not available. Cannot send packet.")
            return
        client_socket.sendall(data)
    except Exception as e:
        print(f"Error sending packet: {e}")
        sys.exit(1)


def handle_user_input() -> None:
    """Handles user input, now with commands."""
    global username, password, logged_in, login_failed
    time.sleep(1)
    while (username is None or password is None) and not logged_in:  # Force login/registration
        username = input("Username: ")
        password = input("Password: ")
        packet = ClientPacket(type=MessageType.CREATE_USER_REQUEST, data={"username": username, "password": password})
        send_packet_to_server(packet)
        print("Login/Registration attempt sent. Waiting for server response...")
        while not logged_in and not login_failed:
            pass
        if login_failed:
            print("Login/Registration failed. Try again.")
            username = None
            password = None
            logged_in = False
            login_failed = False
        else:
            print("Logged in successfully.")
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
                    print("Usage: send <recipient> <message>")
                else:
                    recipient = parts[1]
                    message = " ".join(parts[2:])  # Join the rest as the message
                    packet = ClientPacket(type=MessageType.SEND_MESSAGE, data={"sender": username, "recipient": recipient, "message": message, "password": password})
                    send_packet_to_server(packet)
            elif command == "delete":
                if len(parts) != 2:
                    print("Usage: delete <message_id>")
                else:
                    message_id = parts[1]
                    packet = ClientPacket(type=MessageType.DELETE_MESSAGE, data={"message_id": message_id, "password": password})
                    send_packet_to_server(packet)
            elif command == "delete_account":
                packet = ClientPacket(type=MessageType.DELETE_ACCOUNT, data={"password": password})
                send_packet_to_server(packet)
                print("Account deleted.")
                break
            elif command == "request_messages":
                packet = ClientPacket(type=MessageType.REQUEST_MESSAGES, data = {"sender": username, "password": password})
                send_packet_to_server(packet)
            elif command == "exit":
                break # Exit the loop and close the connection
            else:
                print("Invalid command.")

        except EOFError:
            print("EOF (Ctrl+D) received. Exiting.")
            break
        except Exception as e:
            print(f"Error processing input: {e}")
            break

    client_socket.close()
    sys.exit(0)


def receive_data() -> None:
    """Receives data from the server in a loop."""
    while True:
        try:
            data: bytes = client_socket.recv(1024)
            if not data:  # Server disconnected
                print("Server disconnected.")
                break
            process_server_message(data)
        except OSError as e:
            print(f"Socket error: {e}")
            break
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
    client_socket.close()
    sys.exit(0)


def on_startup() -> None:
    """Function that runs on client startup."""
    try:
        send_packet_to_server(ServerPacket(type=MessageType.REQUEST_PUBLIC_KEY))
    except Exception as e:
        print(f"Error on startup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    SERVER_IP: str = "127.0.0.1"  # Replace with the server's IP address
    SERVER_PORT: int = 12345  # Replace with the server's port

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