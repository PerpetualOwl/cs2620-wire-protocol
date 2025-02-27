import grpc
import time
import uuid
import hashlib
import re
from concurrent import futures
import threading
import logging

# Import the generated gRPC code
import chat_pb2
import chat_pb2_grpc

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('chat_server')

class ChatServicer(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self):
        # In-memory storage (would use a database in production)
        self.accounts = {}  # username -> {password_hash, online_status}
        self.messages = {}  # username -> [Message]
        self.online_users = {}  # username -> list of message queues for streaming
        self.sessions = {}  # session_token -> username
        self.session_lock = threading.Lock()
        
    def validate_session(self, session_token, username=None):
        """Validate session token and optionally check if it belongs to the provided username"""
        with self.session_lock:
            if session_token not in self.sessions:
                return False
            if username and self.sessions[session_token] != username:
                return False
            return True
            
    def _generate_session_token(self, username):
        """Generate a unique session token for a user"""
        token = str(uuid.uuid4())
        with self.session_lock:
            self.sessions[token] = username
        return token
        
    def _invalidate_session(self, session_token):
        """Invalidate a session token"""
        with self.session_lock:
            if session_token in self.sessions:
                del self.sessions[session_token]
                
    def _match_pattern(self, username, pattern):
        """Match username against a wildcard pattern"""
        if not pattern:
            return True
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        return re.match(f"^{regex_pattern}$", username) is not None
        
    def CreateAccount(self, request, context):
        username = request.username
        password_hash = request.password_hash
        
        # Check if account exists
        if username in self.accounts:
            return chat_pb2.CreateAccountResponse(
                success=False,
                message="Account already exists. Please login.",
                account_exists=True
            )
            
        # Create new account
        self.accounts[username] = {"password_hash": password_hash}
        self.messages[username] = []
        logger.info(f"Created new account for user: {username}")
        
        return chat_pb2.CreateAccountResponse(
            success=True,
            message="Account created successfully",
            account_exists=False
        )
        
    def Login(self, request, context):
        username = request.username
        password_hash = request.password_hash
        
        # Check if account exists
        if username not in self.accounts:
            return chat_pb2.LoginResponse(
                success=False,
                message="Invalid username",
                unread_message_count=0
            )
            
        # Verify password
        if self.accounts[username]["password_hash"] != password_hash:
            return chat_pb2.LoginResponse(
                success=False,
                message="Invalid password",
                unread_message_count=0
            )
            
        # Generate session token
        session_token = self._generate_session_token(username)
        
        # Mark user as online
        self.accounts[username]["online"] = True
        self.online_users[username] = []
        
        # Count unread messages
        unread_count = sum(1 for msg in self.messages[username] if not msg.read)
        logger.info(f"User {username} logged in. Unread messages: {unread_count}")
        
        return chat_pb2.LoginResponse(
            success=True,
            message="Login successful",
            unread_message_count=unread_count,
            session_token=session_token
        )
        
    def ListAccounts(self, request, context):
        if not self.validate_session(request.session_token):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
            
        pattern = request.pattern
        page = max(1, request.page)
        page_size = max(10, min(100, request.page_size))  # Between 10 and 100
        
        # Filter accounts based on pattern
        filtered_accounts = [
            username for username in self.accounts.keys()
            if self._match_pattern(username, pattern)
        ]
        
        # Calculate pagination
        total_accounts = len(filtered_accounts)
        total_pages = (total_accounts + page_size - 1) // page_size
        
        # Get accounts for current page
        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_accounts)
        
        page_accounts = filtered_accounts[start_idx:end_idx]
        
        return chat_pb2.ListAccountsResponse(
            usernames=page_accounts,
            total_accounts=total_accounts,
            current_page=page,
            total_pages=total_pages
        )
        
    def DeleteAccount(self, request, context):
        username = request.username
        password_hash = request.password_hash
        
        # Validate session
        if not self.validate_session(request.session_token, username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
            
        # Check if account exists
        if username not in self.accounts:
            return chat_pb2.DeleteAccountResponse(
                success=False,
                message="Account not found"
            )
            
        # Verify password
        if self.accounts[username]["password_hash"] != password_hash:
            return chat_pb2.DeleteAccountResponse(
                success=False,
                message="Invalid password"
            )
            
        # Delete account and associated messages
        del self.accounts[username]
        del self.messages[username]
        
        # Remove from online users if logged in
        if username in self.online_users:
            del self.online_users[username]
            
        # Delete messages sent to other users
        for recipient, msgs in self.messages.items():
            self.messages[recipient] = [
                msg for msg in msgs if msg.sender != username
            ]
            
        logger.info(f"Account deleted: {username}")
        
        return chat_pb2.DeleteAccountResponse(
            success=True,
            message="Account deleted successfully"
        )
        
    def SendMessage(self, request, context):
        sender = request.sender
        recipient = request.recipient
        content = request.content
        
        # Validate session
        if not self.validate_session(request.session_token, sender):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
            
        # Check if sender and recipient exist
        if sender not in self.accounts:
            return chat_pb2.SendMessageResponse(
                success=False,
                message="Sender account not found"
            )
            
        if recipient not in self.accounts:
            return chat_pb2.SendMessageResponse(
                success=False,
                message="Recipient account not found"
            )
            
        # Create message
        message_id = str(uuid.uuid4())
        message = chat_pb2.Message(
            message_id=message_id,
            sender=sender,
            recipient=recipient,
            content=content,
            timestamp=int(time.time()),
            read=False
        )
        
        # If recipient is online, deliver immediately
        if recipient in self.online_users and self.online_users[recipient]:
            for queue in self.online_users[recipient]:
                queue.append(message)
            logger.info(f"Message from {sender} to {recipient} delivered immediately")
        else:
            # Store message for later delivery
            self.messages[recipient].append(message)
            logger.info(f"Message from {sender} to {recipient} queued for later delivery")
        
        
        response =  chat_pb2.SendMessageResponse(
            success=True,
            message="Message sent",
            message_id=message_id
        )
        print(len(response.SerializeToString()))
        return response
        
    def GetMessages(self, request, context):
        username = request.username
        limit = request.limit if request.limit > 0 else 10
        
        # Validate session
        if not self.validate_session(request.session_token, username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
            
        # Check if account exists
        if username not in self.accounts:
            context.abort(grpc.StatusCode.NOT_FOUND, "Account not found")
            
        # Get messages
        user_messages = self.messages[username][:limit]
        remaining = len(self.messages[username]) - limit
        
        # Mark retrieved messages as read
        for msg in user_messages:
            msg.read = True
            
        # Update messages list (remove retrieved messages)
        self.messages[username] = self.messages[username][limit:]
        
        logger.info(f"Retrieved {len(user_messages)} messages for {username}. {remaining} remaining.")
        
        return chat_pb2.GetMessagesResponse(
            messages=user_messages,
            remaining_messages=remaining
        )
        
    def DeleteMessages(self, request, context):
        username = request.username
        message_ids = set(request.message_ids)
        
        # Validate session
        if not self.validate_session(request.session_token, username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
            
        # Check if account exists
        if username not in self.accounts:
            context.abort(grpc.StatusCode.NOT_FOUND, "Account not found")
            
        # Delete messages
        original_count = len(self.messages[username])
        self.messages[username] = [
            msg for msg in self.messages[username]
            if msg.message_id not in message_ids
        ]
        deleted_count = original_count - len(self.messages[username])
        
        logger.info(f"Deleted {deleted_count} messages for user {username}")
        
        return chat_pb2.DeleteMessagesResponse(
            success=True,
            message=f"Deleted {deleted_count} messages",
            deleted_count=deleted_count
        )
        
    def ReceiveMessages(self, request, context):
        username = request.username
        
        # Validate session
        if not self.validate_session(request.session_token, username):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid session")
            
        # Check if account exists
        if username not in self.accounts:
            context.abort(grpc.StatusCode.NOT_FOUND, "Account not found")
            
        # Create message queue for this stream
        message_queue = []
        
        # Register this queue for real-time message delivery
        if username not in self.online_users:
            self.online_users[username] = []
        self.online_users[username].append(message_queue)
        
        try:
            while context.is_active():
                # Check for new messages
                if message_queue:
                    yield message_queue.pop(0)
                else:
                    time.sleep(0.5)  # Wait a bit before checking again
        finally:
            # Clean up when the stream ends
            if username in self.online_users and message_queue in self.online_users[username]:
                self.online_users[username].remove(message_queue)
                if not self.online_users[username]:
                    del self.online_users[username]
                    self.accounts[username]["online"] = False

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    logger.info("Server started on port 50051")
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Server shutting down")
        server.stop(0)

if __name__ == '__main__':
    serve()