import os
import tempfile
import shutil
import sqlite3
import threading
from unittest.mock import MagicMock, patch, PropertyMock
import logging
from database import DatabaseManager
from raft import NodeState

# Configure logging for tests
logging.basicConfig(level=logging.WARNING)


class TestDatabaseManager(DatabaseManager):
    """A modified version of DatabaseManager for testing that works with in-memory databases"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection = None
        self._lock = threading.Lock()
        
        # Skip directory creation for in-memory databases
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_db()


def create_in_memory_database():
    """Create an in-memory database for testing"""
    # Get the absolute path to schema.sql
    current_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(current_dir, 'schema.sql')
    
    # Initialize the database with schema
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    
    # Read schema file
    with open(schema_path, 'r') as f:
        schema = f.read()
        
    # Execute schema
    conn.executescript(schema)
    conn.commit()
    conn.close()
    
    # Create the database manager with the in-memory database
    return TestDatabaseManager(":memory:")

class TestDatabaseHelper:
    """Helper class for setting up test databases with proper permissions"""
    
    @staticmethod
    def create_test_db():
        """Create a temporary test database with proper permissions"""
        # Create a temporary directory
        test_dir = tempfile.mkdtemp()
        
        # Create a database file with proper permissions
        db_path = os.path.join(test_dir, "test.db")
        
        # Get the absolute path to schema.sql
        current_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(current_dir, 'schema.sql')
        
        # Initialize the database with schema
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        conn = sqlite3.connect(db_path)
        conn.executescript(schema)
        conn.commit()
        conn.close()
        
        return test_dir, db_path
    
    @staticmethod
    def cleanup_test_db(test_dir):
        """Clean up the temporary test directory"""
        shutil.rmtree(test_dir)


def mock_raft_node():
    """Create a mock RaftNode that allows testing without actual consensus"""
    mock_node = MagicMock()
    type(mock_node).state = PropertyMock(return_value=NodeState.LEADER)
    mock_node.replicate_log.return_value = True
    return mock_node


def mock_db_manager():
    """Create a mock DatabaseManager that returns success for all operations"""
    mock_db = MagicMock()
    
    # User operations
    mock_db.create_user.return_value = True
    mock_db.get_user.return_value = {"username": "testuser", "password_hash": "hashed_password"}
    mock_db.delete_user.return_value = True
    mock_db.list_users.return_value = ["user1", "user2", "admin"]
    
    # Message operations
    mock_db.save_message.return_value = True
    mock_db.get_messages.return_value = [
        {"message_id": "msg1", "sender": "sender", "recipient": "recipient", 
         "content": "Message 1", "timestamp": 1234567890, "read": 0},
        {"message_id": "msg2", "sender": "sender", "recipient": "recipient", 
         "content": "Message 2", "timestamp": 1234567891, "read": 0}
    ]
    
    # Session operations
    mock_db.create_session.return_value = True
    mock_db.validate_session.return_value = True
    
    return mock_db


def mock_grpc_context():
    """Create a mock gRPC context"""
    context = MagicMock()
    return context
