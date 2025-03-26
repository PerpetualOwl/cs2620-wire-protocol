import sqlite3
import threading
import time
import os
import json
from typing import List, Dict, Optional, Any, Tuple

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection = None
        self._lock = threading.Lock()
        
        # Ensure database directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_db()
        
    def _init_db(self):
        """Initialize the database with schema"""
        with open('schema.sql', 'r') as f:
            schema = f.read()
            
        with self._get_connection() as conn:
            conn.executescript(schema)
            conn.commit()
            
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(threading.current_thread(), 'db_connection'):
            threading.current_thread().db_connection = sqlite3.connect(self.db_path)
            threading.current_thread().db_connection.row_factory = sqlite3.Row
        return threading.current_thread().db_connection
        
    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a query with thread safety"""
        with self._lock:
            conn = self._get_connection()
            return conn.execute(query, params)
            
    def commit(self):
        """Commit changes with thread safety"""
        with self._lock:
            self._get_connection().commit()
            
    # User operations
    def create_user(self, username: str, password_hash: str) -> bool:
        try:
            print(f"[DATABASE] Creating user: {username}")
            # First check if user already exists
            existing_user = self.get_user(username)
            if existing_user:
                print(f"[DATABASE] User {username} already exists")
                return False
                
            print(f"[DATABASE] Inserting user {username} into database")
            self.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, int(time.time()))
            )
            self.commit()
            print(f"[DATABASE] User {username} created successfully")
            return True
        except sqlite3.IntegrityError as e:
            print(f"[DATABASE] IntegrityError creating user {username}: {e}")
            return False
        except Exception as e:
            print(f"[DATABASE] Error creating user {username}: {e}")
            return False
            
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        cursor = self.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
        
    def delete_user(self, username: str) -> bool:
        self.execute("DELETE FROM users WHERE username = ?", (username,))
        self.commit()
        return True
        
    def list_users(self, pattern: str = None) -> List[str]:
        if pattern:
            pattern = pattern.replace('*', '%').replace('?', '_')
            cursor = self.execute(
                "SELECT username FROM users WHERE username LIKE ?",
                (pattern,)
            )
        else:
            cursor = self.execute("SELECT username FROM users")
        return [row['username'] for row in cursor.fetchall()]
        
    # Message operations
    def save_message(self, message_id: str, sender: str, recipient: str, 
                    content: str, timestamp: int) -> bool:
        try:
            self.execute(
                """INSERT INTO messages 
                   (message_id, sender, recipient, content, timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                (message_id, sender, recipient, content, timestamp)
            )
            self.commit()
            return True
        except sqlite3.IntegrityError:
            return False
            
    def get_messages(self, username: str, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self.execute(
            """SELECT * FROM messages 
               WHERE recipient = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (username, limit)
        )
        return [dict(row) for row in cursor.fetchall()]
        
    def mark_messages_read(self, message_ids: List[str]):
        self.execute(
            "UPDATE messages SET read = 1 WHERE message_id IN ({})".format(
                ','.join('?' * len(message_ids))
            ),
            tuple(message_ids)
        )
        self.commit()
        
    def delete_messages(self, message_ids: List[str]):
        self.execute(
            "DELETE FROM messages WHERE message_id IN ({})".format(
                ','.join('?' * len(message_ids))
            ),
            tuple(message_ids)
        )
        self.commit()
        
    # Session operations
    def create_session(self, session_token: str, username: str, 
                      expires_in: int = 86400) -> bool:
        try:
            now = int(time.time())
            self.execute(
                """INSERT INTO sessions 
                   (session_token, username, created_at, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (session_token, username, now, now + expires_in)
            )
            self.commit()
            return True
        except sqlite3.IntegrityError:
            return False
            
    def validate_session(self, session_token: str, username: str = None) -> bool:
        now = int(time.time())
        if username:
            cursor = self.execute(
                """SELECT 1 FROM sessions 
                   WHERE session_token = ? AND username = ? 
                   AND expires_at > ?""",
                (session_token, username, now)
            )
        else:
            cursor = self.execute(
                "SELECT 1 FROM sessions WHERE session_token = ? AND expires_at > ?",
                (session_token, now)
            )
        return cursor.fetchone() is not None
        
    def delete_session(self, session_token: str):
        self.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
        self.commit()
        
    # Raft state operations
    def save_raft_state(self, key: str, value: Any):
        self.execute(
            "INSERT OR REPLACE INTO raft_state (key, value) VALUES (?, ?)",
            (key, json.dumps(value))
        )
        self.commit()
        
    def get_raft_state(self, key: str) -> Optional[Any]:
        cursor = self.execute(
            "SELECT value FROM raft_state WHERE key = ?",
            (key,)
        )
        row = cursor.fetchone()
        return json.loads(row['value']) if row else None
        
    def append_raft_log(self, term: int, operation_type: str, data: bytes) -> int:
        cursor = self.execute(
            """INSERT INTO raft_log (term, operation_type, data)
               VALUES (?, ?, ?)""",
            (term, operation_type, data)
        )
        self.commit()
        return cursor.lastrowid
        
    def get_raft_log_entry(self, index: int) -> Optional[Dict[str, Any]]:
        cursor = self.execute(
            "SELECT * FROM raft_log WHERE log_index = ?",
            (index,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
        
    def get_last_log_entry(self) -> Tuple[int, int]:
        """Return (index, term) of last log entry"""
        cursor = self.execute(
            "SELECT log_index, term FROM raft_log ORDER BY log_index DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return (row['log_index'], row['term']) if row else (0, 0)
        
    def delete_logs_from(self, index: int):
        """Delete all log entries from index onwards"""
        self.execute("DELETE FROM raft_log WHERE log_index >= ?", (index,))
        self.commit() 