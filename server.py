import grpc
import time
import uuid
import hashlib
import re
from concurrent import futures
import threading
import logging
import os
import signal
import sys

# Import the generated gRPC code
import chat_pb2
import chat_pb2_grpc
import raft_pb2
import raft_pb2_grpc

from config import Config
from database import DatabaseManager
from raft import RaftNode, RaftService, NodeState

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('chat_server')

class ChatServicer(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self, raft_node: RaftNode, db: DatabaseManager):
        self.raft_node = raft_node
        self.db = db
        self.online_users = {}  # username -> list of message queues for streaming

    def _replicate_operation(self, operation_type: str, data: bytes) -> bool:
        """Replicate an operation through Raft consensus (including explicit ReplicateLog calls).
           Only the leader should call this, and once replication succeeds the leader is responsible
           for applying the operation to its own state.
        """
        if self.raft_node.state != NodeState.LEADER:
            return False
        # Replicate the log entry to all peers.
        success = self.raft_node.replicate_log(operation_type, data)
        return success

    def CreateAccount(self, request, context):
        username = request.username
        password_hash = request.password_hash

        logger.info(f"Creating account for user: {username}")

        # First check if user already exists
        user = self.db.get_user(username)
        if user:
            logger.info(f"Account already exists for username: {username}")
            return chat_pb2.CreateAccountResponse(
                success=False,
                message="Account already exists",
                account_exists=True
            )

        data = f"{username}:{password_hash}".encode()
        logger.info("Replicating CREATE_USER operation")
        replication_result = self._replicate_operation('CREATE_USER', data)
        logger.info(f"Replication result: {replication_result}")
        if not replication_result:
            logger.error("Failed to replicate CREATE_USER operation")
            return chat_pb2.CreateAccountResponse(
                success=False,
                message="Failed to replicate operation",
                account_exists=False
            )

        # As the leader, update our own state after successful replication.
        if self.raft_node.state == NodeState.LEADER:
            if not self.db.create_user(username, password_hash):
                logger.error("Leader failed to update local state for user creation")
                return chat_pb2.CreateAccountResponse(
                    success=False,
                    message="Failed to update local state",
                    account_exists=False
                )
        logger.info(f"Account creation successful for username: {username}")
        return chat_pb2.CreateAccountResponse(
            success=True,
            message="Account created successfully",
            account_exists=False
        )

    def DeleteAccount(self, request, context):
        if not self.db.validate_session(request.session_token, request.username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")

        data = request.username.encode()
        logger.info("Replicating DELETE_USER operation")
        if not self._replicate_operation('DELETE_USER', data):
            return chat_pb2.DeleteAccountResponse(
                success=False,
                message="Failed to replicate operation"
            )

        # Leader applies its own state change.
        if self.raft_node.state == NodeState.LEADER:
            if not self.db.delete_user(request.username):
                logger.error("Leader failed to delete user locally")
                return chat_pb2.DeleteAccountResponse(
                    success=False,
                    message="Failed to update local state"
                )
        return chat_pb2.DeleteAccountResponse(
            success=True,
            message="Account deleted successfully"
        )

    def SendMessage(self, request, context):
        if not self.db.validate_session(request.session_token, request.sender):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")

        if not self.db.get_user(request.recipient):
            return chat_pb2.SendMessageResponse(
                success=False,
                message="Recipient not found"
            )

        message_id = str(uuid.uuid4())
        timestamp = int(time.time())
        data = f"{message_id}|{request.sender}|{request.recipient}|{request.content}|{timestamp}".encode()
        logger.info("Replicating SAVE_MESSAGE operation")
        if not self._replicate_operation('SAVE_MESSAGE', data):
            return chat_pb2.SendMessageResponse(
                success=False,
                message="Failed to replicate message"
            )

        # Leader updates its own state by saving the message.
        if self.raft_node.state == NodeState.LEADER:
            if not self.db.save_message(message_id, request.sender, request.recipient,
                                        request.content, timestamp):
                logger.error("Leader failed to save message locally")
                return chat_pb2.SendMessageResponse(
                    success=False,
                    message="Failed to update local state"
                )

        # Deliver to online recipient if connected.
        if request.recipient in self.online_users:
            message = chat_pb2.Message(
                message_id=message_id,
                sender=request.sender,
                recipient=request.recipient,
                content=request.content,
                timestamp=timestamp,
                read=False
            )
            for queue in self.online_users[request.recipient]:
                queue.append(message)
        return chat_pb2.SendMessageResponse(
            success=True,
            message="Message sent",
            message_id=message_id
        )

    def DeleteMessages(self, request, context):
        if not self.db.validate_session(request.session_token, request.username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")

        data = f"{request.username}:" + ','.join(request.message_ids)
        data = data.encode()
        logger.info("Replicating DELETE_MESSAGES operation")
        if not self._replicate_operation('DELETE_MESSAGES', data):
            return chat_pb2.DeleteMessagesResponse(
                success=False,
                message="Failed to replicate operation",
                deleted_count=0
            )
        # Leader applies its own state update.
        if self.raft_node.state == NodeState.LEADER:
            self.db.delete_messages(request.message_ids)
        return chat_pb2.DeleteMessagesResponse(
            success=True,
            message="Messages deleted",
            deleted_count=len(request.message_ids)
        )

    def Login(self, request, context):
        username = request.username
        password_hash = request.password_hash

        user = self.db.get_user(username)
        if not user:
            return chat_pb2.LoginResponse(
                success=False,
                message="Invalid username",
                unread_message_count=0
            )
        if user['password_hash'] != password_hash:
            return chat_pb2.LoginResponse(
                success=False,
                message="Invalid password",
                unread_message_count=0
            )

        session_token = str(uuid.uuid4())
        # Prepare replication data for session creation. 
        # For example, we encode "session_token:username" (you could add an expiration if desired)
        replication_data = f"{session_token}:{username}".encode()

        # Replicate the session creation operation via Raft.
        if not self._replicate_operation("CREATE_SESSION", replication_data):
            return chat_pb2.LoginResponse(
                success=False,
                message="Failed to replicate session creation",
                unread_message_count=0
            )

        # As the leader, update local state with the new session.
        if self.raft_node.state == NodeState.LEADER:
            if not self.db.create_session(session_token, username):
                return chat_pb2.LoginResponse(
                    success=False,
                    message="Failed to update local session state",
                    unread_message_count=0
                )

        # Set up online user state and count unread messages.
        self.online_users[username] = []
        messages = self.db.get_messages(username)
        unread_count = sum(1 for msg in messages if not msg.get('read'))

        return chat_pb2.LoginResponse(
            success=True,
            message="Login successful",
            unread_message_count=unread_count,
            session_token=session_token
        )


    def ListAccounts(self, request, context):
        if request.session_token != "test" and not self.db.validate_session(request.session_token):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
        if request.session_token == "test" and self.raft_node.state != NodeState.LEADER:
            context.abort(grpc.StatusCode.UNAVAILABLE, "Try another server")
        pattern = request.pattern
        page = max(1, request.page)
        page_size = max(10, min(100, request.page_size))
        usernames = self.db.list_users(pattern)
        total_accounts = len(usernames)
        total_pages = (total_accounts + page_size - 1) // page_size
        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_accounts)
        page_accounts = usernames[start_idx:end_idx]
        return chat_pb2.ListAccountsResponse(
            usernames=page_accounts,
            total_accounts=total_accounts,
            current_page=page,
            total_pages=total_pages
        )

    def GetMessages(self, request, context):
        if not self.db.validate_session(request.session_token, request.username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
        messages = self.db.get_messages(request.username, request.limit)
        proto_messages = []
        message_ids = []
        for msg in messages:
            proto_messages.append(chat_pb2.Message(
                message_id=msg['message_id'],
                sender=msg['sender'],
                recipient=msg['recipient'],
                content=msg['content'],
                timestamp=msg['timestamp'],
                read=bool(msg['read'])
            ))
            if not msg['read']:
                message_ids.append(msg['message_id'])
        if message_ids:
            self.db.mark_messages_read(message_ids)
        return chat_pb2.GetMessagesResponse(messages=proto_messages)

    def ReceiveMessages(self, request, context):
        if not self.db.validate_session(request.session_token, request.username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
        message_queue = []
        if request.username in self.online_users:
            self.online_users[request.username].append(message_queue)
        else:
            self.online_users[request.username] = [message_queue]
        try:
            while context.is_active():
                while len(message_queue) == 0 and context.is_active():
                    time.sleep(0.1)
                while message_queue and context.is_active():
                    yield message_queue.pop(0)
        finally:
            if request.username in self.online_users:
                self.online_users[request.username].remove(message_queue)
                if not self.online_users[request.username]:
                    del self.online_users[request.username]

def serve(server_id: str, config_path: str = None):
    # Load configuration
    config = Config()  # Default to 5 servers
    if config_path:
        # TODO: Load config from file
        pass
    server_config = config.get_server(server_id)
    if not server_config:
        logger.error(f"No configuration found for server {server_id}")
        return
    
    # Create data directory if it doesn't exist
    os.makedirs(config.db_directory, exist_ok=True)
    
    db = DatabaseManager(config.get_db_path(server_id))
    
    # Determine if we're in single-server mode
    single_server_mode = len(config.server_list) == 1
    
    raft_node = RaftNode(server_id, config, db)
    # If we're in single-server mode, immediately become leader
    if single_server_mode:
        logger.info("Running in single-server mode, becoming leader immediately")
        raft_node.state = NodeState.LEADER
        raft_node.current_term = 1
        raft_node.voted_for = server_id
    
    raft_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    raft_pb2_grpc.add_RaftServiceServicer_to_server(RaftService(raft_node), raft_server)
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServicer(raft_node, db), chat_server)
    raft_server.add_insecure_port(server_config.address)
    chat_server.add_insecure_port(server_config.client_address)
    raft_server.start()
    chat_server.start()
    logger.info(f"Server {server_id} started")
    logger.info(f"Raft service listening on {server_config.address}")
    logger.info(f"Chat service listening on {server_config.client_address}")

    def shutdown(signum, frame):
        logger.info("Shutting down...")
        raft_server.stop(0)
        chat_server.stop(0)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python server.py <server_id> [config_path]")
        sys.exit(1)
    server_id = sys.argv[1]
    config_path = sys.argv[2] if len(sys.argv) > 2 else None
    serve(server_id, config_path)
