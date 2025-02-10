import hashlib, json, pydantic, os, struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Optional, List, Union, Tuple
from enum import Enum
from pydantic import BaseModel, model_validator, validator
from datetime import datetime

SERVER_IP = "127.0.0.1"
SERVER_PORT = 33259

USE_CUSTOM_WIRE_PROTOCOL = True

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

def encrypt(public_pem: bytes, message: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_pem)
    
    # Generate a random AES key
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(12)  # 96-bit IV for AES-GCM
    
    # Encrypt the message with AES-GCM
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag  # GCM authentication tag
    
    # Encrypt the AES key using RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return concatenated data: RSA-encrypted AES key + IV + AES-GCM tag + AES ciphertext
    return encrypted_aes_key + iv + tag + ciphertext

def decrypt(private_pem: bytes, encrypted_data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    
    # Extract lengths
    key_size = private_key.key_size // 8  # RSA key size in bytes
    iv_size = 12  # AES-GCM IV size
    tag_size = 16  # AES-GCM tag size
    
    # Split the encrypted data
    encrypted_aes_key = encrypted_data[:key_size]
    iv = encrypted_data[key_size:key_size + iv_size]
    tag = encrypted_data[key_size + iv_size:key_size + iv_size + tag_size]
    ciphertext = encrypted_data[key_size + iv_size + tag_size:]
    
    # Decrypt the AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the message with AES-GCM
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

PACKET_TYPE_CODES = {
    MessageType.REQUEST_PUBLIC_KEY: 0,
    MessageType.PUBLIC_KEY_RESPONSE: 1,
    MessageType.REQUEST_MESSAGES: 2,
    MessageType.ALL_MESSAGES: 3,
    MessageType.SEND_MESSAGE: 4,
    MessageType.DELETE_MESSAGE: 5,
    MessageType.DELETE_ACCOUNT: 6,
    MessageType.MESSAGE_RECEIVED: 7,
    MessageType.MESSAGE_DELETED: 8,
    MessageType.USER_ADDED: 9,
    MessageType.USER_DELETED: 10,
    MessageType.CREATE_USER_REQUEST: 11,
    MessageType.CREATE_USER_RESPONSE: 12,
}
PACKET_TYPE_CODES_REV = {v: k for k, v in PACKET_TYPE_CODES.items()}

# Type tags for our TLV encoding:
TAG_STRING = 1    # Value is a string (encoded as 2-byte length + UTF-8 bytes)
TAG_BOOL   = 2    # Value is a boolean (1 byte: 0 or 1)
TAG_INT    = 3    # Value is a 4-byte signed integer (big-endian)
TAG_FLOAT  = 4    # Value is an 8-byte double (big-endian)
TAG_DICT   = 5    # Value is a dictionary, encoded recursively (1-byte count then TLV key/value pairs)
TAG_LIST   = 6    # Value is a list -- encoded as 1-byte length then each element recursively encoded

def _encode_value(value) -> bytes:
    """
    Recursively encodes a Python value into TLV bytes.
    If the value is a datetime, it is converted to ISO format (a string).
    """
    # Handle datetime by converting to a string.
    if isinstance(value, datetime):
        value = value.isoformat()
        
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        # 2-byte length (unsigned short, network order) then the bytes.
        return struct.pack("!B H", TAG_STRING, len(encoded)) + encoded
    elif isinstance(value, bool):
        return struct.pack("!B B", TAG_BOOL, 1 if value else 0)
    elif isinstance(value, int):
        return struct.pack("!B i", TAG_INT, value)
    elif isinstance(value, float):
        return struct.pack("!B d", TAG_FLOAT, value)
    elif isinstance(value, dict):
        encoded_dict = _encode_dict(value)
        return struct.pack("!B", TAG_DICT) + encoded_dict
    elif isinstance(value, list):
        # For a list, first encode the number of elements as an unsigned byte.
        encoded = struct.pack("!B B", TAG_LIST, len(value))
        for elem in value:
            encoded += _encode_value(elem)
        return encoded
    else:
        # For any other type, convert to string.
        s = str(value)
        encoded = s.encode("utf-8")
        return struct.pack("!B H", TAG_STRING, len(encoded)) + encoded

def _encode_dict(d: dict) -> bytes:
    """
    Encodes a dictionary as follows:
      - 1 byte: number of key/value pairs (keys must be strings)
      - For each pair:
             1 byte: key length (unsigned byte)
             N bytes: key (UTF-8)
             TLV: value (encoded via _encode_value)
    """
    encoded = b""
    # Number of key/value pairs (assuming less than 256 keys)
    encoded += struct.pack("!B", len(d))
    for key, value in d.items():
        key_bytes = key.encode("utf-8")
        # 1 byte for key length then the key bytes.
        encoded += struct.pack("!B", len(key_bytes)) + key_bytes
        encoded += _encode_value(value)
    return encoded

def _decode_value(data: bytes, offset: int) -> Tuple[Union[str, bool, int, float, dict, list], int]:
    """
    Decodes a TLV value starting at the given offset.
    Returns a tuple (value, new_offset).
    """
    tag = data[offset]
    offset += 1
    if tag == TAG_STRING:
        # Next 2 bytes: length of string.
        (strlen,) = struct.unpack_from("!H", data, offset)
        offset += 2
        s = data[offset: offset+strlen].decode("utf-8")
        offset += strlen
        return s, offset
    elif tag == TAG_BOOL:
        (bval,) = struct.unpack_from("!B", data, offset)
        offset += 1
        return bool(bval), offset
    elif tag == TAG_INT:
        (ival,) = struct.unpack_from("!i", data, offset)
        offset += 4
        return ival, offset
    elif tag == TAG_FLOAT:
        (fval,) = struct.unpack_from("!d", data, offset)
        offset += 8
        return fval, offset
    elif tag == TAG_DICT:
        d, offset = _decode_dict(data, offset)
        return d, offset
    elif tag == TAG_LIST:
        # Next byte is the number of elements.
        (length,) = struct.unpack_from("!B", data, offset)
        offset += 1
        lst = []
        for _ in range(length):
            elem, offset = _decode_value(data, offset)
            lst.append(elem)
        return lst, offset
    else:
        # Unknown tag – try to decode as string.
        raise ValueError(f"Unknown TLV tag: {tag}")

def _decode_dict(data: bytes, offset: int) -> Tuple[dict, int]:
    """
    Decodes a dictionary that was encoded with _encode_dict.
    Returns a tuple (dict, new_offset).
    """
    (num_items,) = struct.unpack_from("!B", data, offset)
    offset += 1
    result = {}
    for _ in range(num_items):
        # Get key length and key.
        (keylen,) = struct.unpack_from("!B", data, offset)
        offset += 1
        key = data[offset: offset+keylen].decode("utf-8")
        offset += keylen
        value, offset = _decode_value(data, offset)
        result[key] = value
    return result, offset

def serialize_packet(packet: Union[ClientPacket, ServerPacket]) -> bytes:
    """
    Serializes a ClientPacket or ServerPacket to bytes.
    
    When USE_CUSTOM_WIRE_PROTOCOL is True, the packet is encoded using a
    compact, TLV-based binary wire protocol described in the protocol documentation below.
    Otherwise, JSON is used.
    """
    if USE_CUSTOM_WIRE_PROTOCOL:
        # First byte: the packet type code.
        packet_code = PACKET_TYPE_CODES[packet.type]
        # Encode the data dictionary (if None, use empty dict).
        data_dict = packet.data if packet.data is not None else {}
        encoded_data = _encode_dict(data_dict)
        return struct.pack("!B", packet_code) + encoded_data
    else:
        packet_dict = packet.model_dump()  # Use pydantic v2 export
        packet_json = json.dumps(packet_dict).encode("utf-8")
        return packet_json

def deserialize_packet(packet_bytes: bytes, packet_cls: type[Union[ClientPacket, ServerPacket]]) -> Union[ClientPacket, ServerPacket]:
    """
    Deserializes bytes to a ClientPacket or ServerPacket.
    
    When USE_CUSTOM_WIRE_PROTOCOL is True, the data is expected to be encoded according
    to the TLV-based binary wire protocol described below.
    Otherwise, JSON deserialization is performed.
    """
    if USE_CUSTOM_WIRE_PROTOCOL:
        # The first byte contains the packet type code.
        packet_code = packet_bytes[0]
        try:
            packet_type = PACKET_TYPE_CODES_REV[packet_code]
        except KeyError:
            raise ValueError("Unknown packet type code in custom protocol")
        # Decode the data dictionary from the remaining bytes.
        data_dict, _ = _decode_dict(packet_bytes, offset=1)
        packet_data = {"type": packet_type, "data": data_dict}
        return packet_cls(**packet_data)
    else:
        try:
            packet_json = packet_bytes.decode("utf-8")
            packet_dict = json.loads(packet_json)
            return packet_cls(**packet_dict)
        except (json.JSONDecodeError, pydantic.ValidationError) as e:
            raise ValueError(f"Packet deserialization failed: {e}")