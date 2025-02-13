import socket
import threading
import sys, uuid
from datetime import datetime
from typing import Any, Optional
from utils import *

# Global server keys.
SERVER_PUBLIC_KEY: Optional[bytes] = None
SERVER_PRIVATE_KEY: Optional[bytes] = None

# Global chat data store and user registry.
chat_data = ChatData()
users: dict[str, str] = {}

# Lists and dictionaries to keep track of connections.
clients = []  # list of all connected sockets
authed_clients: dict[str, socket.socket] = {}  # username -> client socket

global_lock = threading.Lock()

def send_packet_to_client(client_socket: socket.socket, packet: ServerPacket, is_public_key_response: bool = False) -> None:
    """Send a packet to a particular client."""
    try:
        print(f"Sending packet to {client_socket.getpeername()}: {packet.type}")
        data: bytes = serialize_packet(packet)
        client_socket.sendall(data)
    except Exception as e:
        print(f"Error sending packet: {e}")
        print(data)

def broadcast_to_clients(packet: ServerPacket, exclude: Optional[socket.socket] = None) -> None:
    """Broadcast a packet to all connected clients except one (if specified)."""
    print(f"Broadcasting packet to all clients: {packet.type}")
    for client_socket in clients:
        if client_socket != exclude:
            send_packet_to_client(client_socket, packet)

def handle_client(client_socket: socket.socket, address):
    """Handle communication with a connected client."""
    print(f"New connection from {address[0]}:{address[1]}")
    
    try:
        while True:
            message = client_socket.recv(65536)
            if not message:
                print(f"Connection closed by {address[0]}:{address[1]}")
                break

            with global_lock:
                # First check if this is an unencrypted public key request.
                try:
                    packet: ClientPacket = deserialize_packet(message, ClientPacket)
                    if packet.type == MessageType.REQUEST_PUBLIC_KEY:
                        send_packet_to_client(client_socket, 
                            ServerPacket(type=MessageType.PUBLIC_KEY_RESPONSE, 
                                         data={"public_key": SERVER_PUBLIC_KEY.decode("utf-8")}))
                        continue
                except Exception:
                    pass

                # Otherwise, attempt decryption.
                try:
                    packet = deserialize_packet(decrypt(SERVER_PRIVATE_KEY, message), ClientPacket)
                except Exception as e:
                    print(f"Error decrypting message from {address[0]}:{address[1]}: {e}")
                    continue

                print(f"Received packet from {address[0]}:{address[1]}: {packet.type}")
                print("\tData:", packet.data)

                # Handle new user creation or login.
                if packet.type == MessageType.CREATE_USER_REQUEST:
                    username = packet.data["username"]
                    password = packet.data["password"]
                    print(f"Creating user: {username}")
                    if username not in users:
                        print(f"User {username} created")
                        users[username] = password
                        chat_data.add_user(username)
                        authed_clients[username] = client_socket
                        broadcast_to_clients(ServerPacket(type=MessageType.USER_ADDED, data={"username": username}), 
                                               exclude=client_socket)
                        send_packet_to_client(client_socket, 
                            ServerPacket(type=MessageType.CREATE_USER_RESPONSE, 
                                         data={"success": True, "message": "New account created!"}))
                    else:
                        if password != users[username]:
                            print(f"Failed login for user {username}: Wrong password")
                            send_packet_to_client(client_socket, 
                                ServerPacket(type=MessageType.CREATE_USER_RESPONSE, 
                                             data={"success": False, "message": "Wrong password!"}))
                        else:
                            print(f"User {username} logged in")
                            authed_clients[username] = client_socket
                            unread_count = len(chat_data.unread_queue.get(username, []))
                            send_packet_to_client(client_socket, 
                                ServerPacket(type=MessageType.CREATE_USER_RESPONSE, 
                                             data={"success": True, "message": f"Logged in! You have {unread_count} unread messages."}))
                    continue

                # For all other packet types, extract username and password for auth.
                username = packet.data.get("sender", packet.data.get("username"))
                password = packet.data["password"]

                if password != users.get(username, None):
                    print(f"Unauthorized access from {address[0]}:{address[1]}")
                    continue

                # Process the remaining packet types using a match-case.
                match packet.type:
                    case MessageType.REQUEST_MESSAGES:
                        print(f"Sending initial messages to {username}")
                        messages: ChatData = chat_data.get_initial()
                        send_packet_to_client(client_socket, 
                            ServerPacket(type=MessageType.INITIAL_CHATDATA, 
                                         data={"messages": messages.model_dump()}))
                    
                    case MessageType.REQUEST_UNREAD_MESSAGES:
                        # New branch for unread messages.
                        # Verify that 'num_messages' is a valid number string.
                        if not str(packet.data.get("num_messages", "")).isdigit():
                            continue
                        num_messages = int(packet.data["num_messages"])
                        print(f"Sending {num_messages} unread message(s) to {username}")
                        unread_msgs = chat_data.pop_unread_messages(username, num_messages=num_messages)
                        # Convert each ChatMessage to its dict representation.
                        unread_msgs_dict = [msg.model_dump() for msg in unread_msgs]
                        send_packet_to_client(client_socket, 
                            ServerPacket(type=MessageType.UNREAD_MESSAGES_RESPONSE, 
                                         data={"messages": unread_msgs_dict}))
                    
                    case MessageType.SEND_MESSAGE:
                        recipient = packet.data["recipient"]
                        msg_text = packet.data["message"]
                        print(f"Message from {username} to {recipient}: {msg_text}")
                        if recipient not in users:
                            print(f"Recipient {recipient} not found")
                            continue
                        if recipient == username:
                            print(f"Sender and recipient are the same ({username}), ignoring.")
                            continue
                        message_obj = ChatMessage(
                            sender=username, 
                            recipient=recipient, 
                            message=msg_text, 
                            message_id=str(uuid.uuid4()), 
                            timestamp=datetime.now()
                        )
                        if chat_data.add_message(message_obj):
                            print("Message logged successfully")
                            # Send a confirmation to the sender.
                            send_packet_to_client(client_socket, 
                                ServerPacket(type=MessageType.MESSAGE_RECEIVED, 
                                             data=message_obj.model_dump()))
                            recipient_active = False
                            # If recipient is online, send the message immediately.
                            for user, rec_socket in authed_clients.items():
                                if user == recipient:
                                    recipient_active = True
                                    print(f"Delivering message to active user {recipient}")
                                    send_packet_to_client(rec_socket, 
                                        ServerPacket(type=MessageType.MESSAGE_RECEIVED, 
                                                     data=message_obj.model_dump()))
                            if not recipient_active:
                                # Otherwise, add the message ID to the recipient's unread queue.
                                chat_data.add_unread_message(recipient, message_obj.message_id)
                        else:
                            print("Failed to add message to logs")
                    
                    case MessageType.DELETE_MESSAGE:
                        print(f"Deleting message for {username}")
                        message_id = packet.data["message_id"]
                        msg_obj = chat_data.get_message(message_id)
                        if chat_data.delete_message(username, message_id, backend=True):
                            print("Message deleted successfully")
                            send_packet_to_client(client_socket, 
                                ServerPacket(type=MessageType.MESSAGE_DELETED, data={"message_id": message_id}))
                            for user, client_sock in authed_clients.items():
                                if user == username or (msg_obj and user == msg_obj.recipient):
                                    send_packet_to_client(client_sock, 
                                        ServerPacket(type=MessageType.MESSAGE_DELETED, data={"message_id": message_id}))
                        else:
                            print("Failed to delete the message")
                    
                    case MessageType.DELETE_ACCOUNT:
                        print(f"Deleting account {username}")
                        if username in users:
                            del users[username]
                            chat_data.delete_user(username)
                            print(f"Account {username} deleted")
                            broadcast_to_clients(ServerPacket(type=MessageType.USER_DELETED, data={"username": username}),
                                                   exclude=client_socket)
                            send_packet_to_client(client_socket, 
                                ServerPacket(type=MessageType.USER_DELETED, data={"username": username}))
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
        client_socket.close()
        # Remove the client from authed_clients if present.
        for user, sock in list(authed_clients.items()):
            if sock == client_socket:
                del authed_clients[user]
                break
        if client_socket in clients:
            clients.remove(client_socket)
        print(f"Closed connection with {address[0]}:{address[1]}")

def main():
    global SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY
    SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_key_pair()
    server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind((SERVER_IP, SERVER_PORT))
        server_socket.listen(5)
        print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

        while True:
            client_socket, address = server_socket.accept()
            clients.append(client_socket)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        for c in clients:
            c.close()
        server_socket.close()

if __name__ == "__main__":
    main()