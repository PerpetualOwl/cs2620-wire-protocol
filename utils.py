import hashlib, json, pydantic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from typing import Optional, List, Union
from enum import Enum
from pydantic import BaseModel, model_validator, validator
from datetime import datetime

SERVER_IP = "127.0.0.1"
SERVER_PORT = 33256

class MessageType(str, Enum):
    REQUEST_PUBLIC_KEY = "request_public_key"
    PUBLIC_KEY_RESPONSE = "public_key_response"
    REQUEST_MESSAGES = "request_messages"
    ALL_MESSAGES = "all_messages"
    SEND_MESSAGE = "send_message"
    DELETE_MESSAGE = "delete_message"
    DELETE_ACCOUNT = "delete_account"
    MESSAGE_RECEIVED = "message_received"
    MESSAGE_DELETED = "message_deleted"
    USER_ADDED = "user_added"
    USER_DELETED = "user_deleted"
    CREATE_USER_REQUEST = "create_user_request"
    CREATE_USER_RESPONSE = "create_user_response"


class ClientPacket(BaseModel):
    type: MessageType
    data: Optional[dict] = None  # Use a dictionary for flexible data

    @validator("data")
    def validate_data(cls, data, values):
        if "type" not in values:
            return data # validator called before type is set, skip
        packet_type = values["type"]

        required_fields = {
            MessageType.REQUEST_PUBLIC_KEY: [],
            MessageType.REQUEST_MESSAGES: ["sender", "password"],
            MessageType.SEND_MESSAGE: ["sender", "recipient", "message", "password"],
            MessageType.DELETE_MESSAGE: ["username", "message_id", "password"], # or sender and recipient
            MessageType.DELETE_ACCOUNT: ["username", "password"],
            MessageType.CREATE_USER_REQUEST: ["username", "password"],
        }

        if packet_type in required_fields:
            for field in required_fields[packet_type]:
                if data is None or field not in data:
                    raise ValueError(f"Missing required field '{field}' for message type '{packet_type}'")
        return data


class ServerPacket(BaseModel):
    type: MessageType
    data: Optional[dict] = None

    @validator("data")
    def validate_data(cls, data, values):
        if "type" not in values:
            return data # validator called before type is set, skip
        packet_type = values["type"]

        required_fields = {
            MessageType.PUBLIC_KEY_RESPONSE: ["public_key"],
            MessageType.MESSAGE_RECEIVED: ["message_id", "recipient"],
            MessageType.MESSAGE_DELETED: ["message_id"],
            MessageType.USER_ADDED: ["username"],
            MessageType.USER_DELETED: ["username"],
            MessageType.CREATE_USER_RESPONSE: ["success", "message"],
            MessageType.ALL_MESSAGES: ["messages"],
        }

        if packet_type in required_fields:
            for field in required_fields[packet_type]:
                if data is None or field not in data:
                    raise ValueError(f"Missing required field '{field}' for message type '{packet_type}'")
        return data


class ChatMessage(BaseModel):
    sender: str
    recipient: str
    message: str
    timestamp: datetime = datetime.now()
    message_id: str # unique ID

    @model_validator(mode="before")
    @classmethod
    def parse_datetime(cls, data):
        if isinstance(data, dict) and "my_datetime" in data and isinstance(data["my_datetime"], str):
            try:
                data["my_datetime"] = datetime.fromisoformat(data["my_datetime"].replace("Z", "+00:00")) # Handle Z timezone
            except ValueError:
                raise ValueError("Invalid datetime format")
        return data
    
    def model_dump(self, *args, **kwargs):
        original_dict = super().model_dump(*args, **kwargs)  # Get the original dict
        def convert_sets_to_lists(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets_to_lists(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets_to_lists(elem) for elem in obj]
            elif isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        return convert_sets_to_lists(original_dict)

class ChatData(BaseModel):
    users: set[str] = set()
    messages: dict[str, ChatMessage] = {}
    message_id_by_user: dict[str, set[str]] = {}

    def get_messages(self, username: str) -> "ChatData":
        messages = {id: msg for id, msg in self.messages.items() if msg.sender == username or msg.recipient == username}
        return ChatData(users=self.users, messages=messages, message_id_by_user=self.message_id_by_user)

    def add_user(self, username: str):
        self.users.add(username)
        self.message_id_by_user[username] = set()
        return True

    def add_message(self, message: ChatMessage):
        if message.sender not in self.users or message.recipient not in self.users:
            self.users.add(message.sender)
            self.users.add(message.recipient)
        self.messages[message.message_id] = message
        
        if message.sender not in self.message_id_by_user:
            self.message_id_by_user[message.sender] = set()
        if message.recipient not in self.message_id_by_user:
            self.message_id_by_user[message.recipient] = set()

        self.message_id_by_user[message.sender].add(message.message_id)
        self.message_id_by_user[message.recipient].add(message.message_id)
        return True

    def delete_message(self, sender: str, message_id: str):
        if (message_id not in self.messages
            or message_id not in self.message_id_by_user[sender]):
            return False
        else:
            msg = self.messages.pop(message_id)
            self.message_id_by_user[msg.sender].remove(message_id)
            self.message_id_by_user[msg.recipient].remove(message_id)
            return True

    def delete_user(self, username: str):
        if username not in self.users:
            return False
        self.users.remove(username)
        for id in self.message_id_by_user[username]:
            self.messages.pop(id)
        self.message_id_by_user.pop(username)
        return True
    
    @model_validator(mode="before")
    @classmethod
    def parse_datetime(cls, data):
        if isinstance(data, dict) and "my_datetime" in data and isinstance(data["my_datetime"], str):
            try:
                data["my_datetime"] = datetime.fromisoformat(data["my_datetime"].replace("Z", "+00:00")) # Handle Z timezone
            except ValueError:
                raise ValueError("Invalid datetime format")
        return data
    
    def model_dump(self, *args, **kwargs):
        original_dict = super().model_dump(*args, **kwargs)  # Get the original dict
        def convert_sets_to_lists(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets_to_lists(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets_to_lists(elem) for elem in obj]
            elif isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        return convert_sets_to_lists(original_dict)

def hash_password(password : str) -> str:
    """
    Hashes a password using SHA256.

    Args:
        password: The password to be hashed.

    Returns:
        The hexadecimal representation of the SHA256 hash digest as a string.
        Raises error if password is not a string.
    """

    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    hash_object = hashlib.sha256(password.encode('utf-8'))
    return hash_object.hexdigest()

def generate_key_pair() -> tuple[bytes, bytes]:
    """Generates a new private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serialize keys (for storage/transmission) - PEM format is common
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # In real app, use a strong passphrase!
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def encrypt(public_pem : bytes, message : bytes) -> bytes:
    """
    Encrypts a message using a public key.

    Args:
        public_pem: The public key in PEM format.
        message: The message to encrypt.

    Returns:
        The encrypted ciphertext.
    """
    public_key = serialization.load_pem_public_key(public_pem)

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(private_pem : bytes, ciphertext : bytes) -> str:
    """
    Decrypts a ciphertext using a private key.

    Args:
        private_pem: The private key in PEM format.
        ciphertext: The ciphertext to decrypt.

    Returns:
        The decrypted plaintext as bytes.
    """
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def serialize_packet(packet: Union[ClientPacket, ServerPacket]) -> bytes:
    """Serializes a ClientPacket or ServerPacket to JSON and then bytes."""
    packet_dict = packet.model_dump()  # Use pydantic v2 method
    packet_json = json.dumps(packet_dict).encode("utf-8")
    return packet_json


def deserialize_packet(packet_bytes: bytes, packet_type: type[Union[ClientPacket, ServerPacket]]) -> Union[ClientPacket, ServerPacket]:
    """Deserializes bytes to a ClientPacket or ServerPacket.

    Args:
        packet_bytes: The bytes to deserialize.
        packet_type: The expected type of the packet (ClientPacket or ServerPacket).

    Returns:
        A ClientPacket or ServerPacket object.
        Raises ValueError if the packet type is incorrect or deserialization fails.
    """

    try:
        packet_json = packet_bytes.decode("utf-8")
        packet_dict = json.loads(packet_json)

        if packet_type == ClientPacket:
             return ClientPacket(**packet_dict)
        elif packet_type == ServerPacket:
             return ServerPacket(**packet_dict)
        else:
            raise ValueError("Invalid packet type. Must be ClientPacket or ServerPacket.")
    except (json.JSONDecodeError, pydantic.ValidationError) as e:
        raise ValueError(f"Packet deserialization failed: {e}")