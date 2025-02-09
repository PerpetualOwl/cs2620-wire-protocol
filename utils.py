import hashlib, json, pydantic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from typing import Optional, List, Union
from pydantic import BaseModel, validator
from enum import Enum
from datetime import datetime

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
            MessageType.DELETE_MESSAGE: ["message_id", "password"], # or sender and recipient
            MessageType.DELETE_ACCOUNT: ["password"],
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
            MessageType.USER_DELETED: ["username"],
            MessageType.CREATE_USER_RESPONSE: ["success", "message"],  # Add success flag and message
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

class ChatData(BaseModel):
    users: set[str] = []
    messages: dict[str, ChatMessage] = {}
    message_id_by_user: dict[str, set[str]] = {}

    def add_message(self, message: ChatMessage):
        self.messages[message.message_id] = message

    def delete_message(self, message_id: str):
        if message_id not in self.messages:
            return
        else:
            msg = self.messages.pop(message_id)
            self.message_id_by_user[msg.sender].remove(message_id)
            self.message_id_by_user[msg.recipient].remove(message_id)

    def delete_user(self, username: str):
        if username not in self.users:
            return
        self.users.remove(username)
        for id in self.message_id_by_user[username]:
            self.messages.pop(id)
        self.message_id_by_user.pop(username)

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

def encrypt(public_pem : bytes, message : str) -> bytes:
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
        message.encode('utf-8'),
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
        The decrypted plaintext as a string.
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
    return plaintext.decode('utf-8')

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