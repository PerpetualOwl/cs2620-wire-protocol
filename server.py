import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Any, Optional, Union, Callable
import sys



from utils import *


SERVER_PUBLIC_KEY: Optional[bytes] = None
SERVER_PRIVATE_KEY: Optional[bytes] = None
chat_data = ChatData()
users: dict[str, str] = {}

# A list to keep track of connected clients (optional)
clients = []

def send_packet_to_client(client_socket: socket.socket, packet: ServerPacket, is_public_key_response: bool = False) -> None:
    """Sends a packet to the server."""
    try:
        data: bytes = serialize_packet(packet)
        client_socket.sendall(data)
    except Exception as e:
        print(f"Error sending packet: {e}")
        sys.exit(1)

def handle_client(client_socket: socket.socket, address):
    """Handles communication with a connected client."""
    print(f"New connection from {address[0]}:{address[1]}")
    
    try:
        while True:
            # Wait to receive data from the client
            message = client_socket.recv(1024)
            if not message:
                # No message means the client has closed the connection
                print(f"Connection closed by {address[0]}:{address[1]}")
                break
            packet = deserialize_packet(message, ClientPacket)
            if packet.type == MessageType.REQUEST_PUBLIC_KEY:
                send_packet_to_client(client_socket, ServerPacket(type=MessageType.PUBLIC_KEY_RESPONSE, data={"public_key": SERVER_PUBLIC_KEY.decode("utf-8")}))
            if packet.type == MessageType.CREATE_USER_REQUEST:
                username = packet.data["username"]
                password = packet.data["password"]
                if username not in users:
                    users[username] = password
                    send_packet_to_client(client_socket, ServerPacket(type=MessageType.CREATE_USER_RESPONSE, data={"success": True, "message": "New account created!"}))
                else:
                    if password != users[username]:
                        send_packet_to_client(client_socket, ServerPacket(type=MessageType.CREATE_USER_RESPONSE, data={"success": False, "message": "Wrong password!"}))
                    else:
                        send_packet_to_client(client_socket, ServerPacket(type=MessageType.CREATE_USER_RESPONSE, data={"success": True, "message": "Logged in!"}))
            if packet.type == MessageType.SEND_MESSAGE:
                sender = packet.data["sender"]
                recipent = packet.data["recipient"]
                message = packet.data["message"]
                password = packet.data["password"]
                if username not in users or recipent not in users:
                    pass
                else:
                    if password != users[username]:
                        pass
                    else:
                        send_packet_to_client(client_socket, ServerPacket(type=MessageType.MESSAGE_RECEIVED, data={"success": True, "message": "Logged in!"}))
            # Echo the message back to the client
            # client_socket.send(message)
    except ConnectionResetError:
        print(f"Connection lost with {address[0]}:{address[1]}")
    except Exception as e:
        print(f"An error occurred with {address[0]}:{address[1]}: {e}")
    finally:
        # Clean up the connection
        client_socket.close()
        if client_socket in clients:
            clients.remove(client_socket)
        print(f"Closed connection with {address[0]}:{address[1]}")

def main():
    # Create a TCP/IP socket
    # Server configuration
    global SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY
    SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_key_pair()
    SERVER_IP: str = "127.0.0.1"  # Replace with the server's IP address
    SERVER_PORT: int = 12345  # Replace with the server's port
    server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Bind the socket to the server address and port
        server_socket.bind((SERVER_IP, SERVER_PORT))
        server_socket.listen(5)  # Listen for up to 5 connections
        print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

        while True:
            # Wait for a new client connection
            client_socket, address = server_socket.accept()
            clients.append(client_socket)
            # Create and start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close all client connections
        for c in clients:
            c.close()
        server_socket.close()

if __name__ == "__main__":
    main()