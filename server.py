import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Any, Optional, Union, Callable
import sys, uuid

from utils import *

SERVER_PUBLIC_KEY: Optional[bytes] = None
SERVER_PRIVATE_KEY: Optional[bytes] = None
chat_data = ChatData()
users: dict[str, str] = {}

# A list to keep track of connected clients (optional)
clients = []
authed_clients: dict[str, socket.socket] = {}

global_lock = threading.Lock()

def send_packet_to_client(client_socket: socket.socket, packet: ServerPacket, is_public_key_response: bool = False) -> None:
    """Sends a packet to the server."""
    print(f"Sending packet to {client_socket.getpeername()}: {packet.type}")
    try:
        data: bytes = serialize_packet(packet)
        client_socket.sendall(data)
    except Exception as e:
        print(f"Error sending packet: {e}")
        sys.exit(1)

def broadcast_to_clients(packet: ServerPacket, exclude: Optional[socket.socket] = None) -> None:
    """Broadcasts a packet to all connected clients."""
    print(f"Broadcasting packet to all clients: {packet.type}")
    for client_socket in clients:
        if client_socket != exclude:
            send_packet_to_client(client_socket, packet)

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
            with global_lock:

                # check if it is an unencrypted public key request
                try:
                    packet: ClientPacket = deserialize_packet(message, ClientPacket)
                    if packet.type == MessageType.REQUEST_PUBLIC_KEY:
                        send_packet_to_client(client_socket, ServerPacket(type=MessageType.PUBLIC_KEY_RESPONSE, data={"public_key": SERVER_PUBLIC_KEY.decode("utf-8")}))
                        continue
                except Exception as _:
                    pass
                
                # otherwise attempt to decrypt the message
                try:
                    packet = deserialize_packet(decrypt(SERVER_PRIVATE_KEY, message), ClientPacket)
                except Exception as e:
                    print(f"Error decrypting message: {e}")
                    continue

                print(f"Received message from {address[0]}:{address[1]}: {packet.type}")
                print("\tData:", packet.data)
                if packet.type == MessageType.CREATE_USER_REQUEST:
                    username = packet.data["username"]
                    password = packet.data["password"]
                    print(f"Creating user: {username}")
                    if username not in users:
                        print(f"User {username} created")
                        users[username] = password
                        chat_data.add_user(username)
                        authed_clients[username] = client_socket
                        broadcast_to_clients(ServerPacket(type=MessageType.USER_ADDED, data={"username": username}), exclude=client_socket)
                        send_packet_to_client(client_socket, ServerPacket(type=MessageType.CREATE_USER_RESPONSE, data={"success": True, "message": "New account created!"}))
                    else:
                        if password != users[username]:
                            print(f"Failed to create user {username}: Wrong password")
                            send_packet_to_client(client_socket, ServerPacket(type=MessageType.CREATE_USER_RESPONSE, data={"success": False, "message": "Wrong password!"}))
                        else:
                            print(f"User {username} logged in")
                            authed_clients[username] = client_socket
                            send_packet_to_client(client_socket, ServerPacket(type=MessageType.CREATE_USER_RESPONSE, data={"success": True, "message": "Logged in!"}))
                    continue
                # check auth
                username = packet.data.get("sender", packet.data.get("username"))
                password = packet.data["password"]

                if password != users.get(username, None):
                    print(f"Unauthorized access from {address[0]}:{address[1]}")
                    continue

                match packet.type:
                    case MessageType.REQUEST_MESSAGES:
                        print(f"Sending messages request result to {username}")
                        messages : ChatData = chat_data.get_messages(username)
                        send_packet_to_client(client_socket, ServerPacket(type=MessageType.ALL_MESSAGES, data={"messages": messages.model_dump()}))

                    case MessageType.SEND_MESSAGE:
                        recipient = packet.data["recipient"]
                        message = packet.data["message"]
                        print(f"Sending message from {username} to {recipient}: {message}")
                        if recipient not in users:
                            print(f"Recipient {recipient} not found")
                            continue
                        if recipient == username:
                            print(f"Recipient {recipient} was same as sender.")
                            continue
                        message_obj = ChatMessage(sender=username, recipient=recipient, message=message, message_id=str(uuid.uuid4()))
                        r = chat_data.add_message(message_obj)
                        # send to recipient
                        if r:
                            print("Message added to logs")
                            send_packet_to_client(client_socket, ServerPacket(type=MessageType.MESSAGE_RECEIVED, data=message_obj.model_dump()))
                            for user, client_socket_recp in authed_clients.items():
                                if user == recipient:
                                    print(f"Sending message to {recipient} through packet")
                                    send_packet_to_client(client_socket_recp, ServerPacket(type=MessageType.MESSAGE_RECEIVED, data=message_obj.model_dump()))
                        else:
                            print("Failed to add message to logs")

                    case MessageType.DELETE_MESSAGE:
                        print(f"Deleting message from {username}")
                        message_id = packet.data["message_id"]
                        message = chat_data.get_message(message_id)
                        r = chat_data.delete_message(username, message_id, True)
                        if r:
                            print("Message deleted from logs")
                            send_packet_to_client(client_socket, ServerPacket(type=MessageType.MESSAGE_DELETED, data={"message_id": message_id}))
                            for user, client_socket_recp in authed_clients.items():
                                if user == username or user == message.recipient:
                                    print(f"Sending message to {username} through packet")
                                    send_packet_to_client(client_socket_recp, ServerPacket(type=MessageType.MESSAGE_DELETED, data={"message_id": message_id}))
                        else:
                            print("Failed to delete message from logs")
                        
                    case MessageType.DELETE_ACCOUNT:
                        print(f"Deleting account {username}")
                        if username in users:
                            del users[username]
                            chat_data.delete_user(username)
                            print(f"User {username} deleted")
                            broadcast_to_clients(ServerPacket(type=MessageType.USER_DELETED, data={"username": username}), exclude=client_socket)
                            send_packet_to_client(client_socket, ServerPacket(type=MessageType.USER_DELETED, data={"username": username}))
                            break
                        else:
                            print(f"User {username} not found")
                    case _:
                        pass
            
    except ConnectionResetError:
        print(f"Connection lost with {address[0]}:{address[1]}")
    except Exception as e:
        print(f"An error occurred with {address[0]}:{address[1]}: {e}")
    finally:
        # Clean up the connection
        client_socket.close()
        for user, client in authed_clients.items():
            if client == client_socket:
                del authed_clients[user]
                break
        if client_socket in clients:
            clients.remove(client_socket)
        print(f"Closed connection with {address[0]}:{address[1]}")

def main():
    # Create a TCP/IP socket
    # Server configuration
    global SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY
    SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_key_pair()
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