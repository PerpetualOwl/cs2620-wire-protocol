import os
import random
from typing import Dict, List
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class ServerConfig:
    def __init__(self, id: str, host: str, port: int):
        self.id = id
        self.host = host
        self.port = port
        self.client_port = port + 1000  # Port for client connections
        
    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"
        
    @property
    def client_address(self) -> str:
        return f"{self.host}:{self.client_port}"

class Config:
    def __init__(self, num_servers=5):
        # Default configuration for local testing
        self.servers: Dict[str, ServerConfig] = {}
        for i in range(1, num_servers+1):
            self.servers["server"+str(i)] = ServerConfig("server" + str(i), "localhost", 50050 + i)
        
        # Election timeout range in milliseconds
        self.election_timeout_min = 500
        self.election_timeout_max = 1000
        
        # Heartbeat interval in milliseconds
        self.heartbeat_interval = 50
        
        # Database configuration
        self.db_directory = "data"
        
        # Load environment-specific configuration
        self._load_from_env()
        
    def _load_from_env(self):
        """Load configuration from environment variables"""
        # Load individual server configurations
        for i in range(1, 6):  # Support up to 5 servers
            server_id = f"server{i}"
            server_ip = os.getenv(f"SERVER{i}_IP")
            if server_ip:
                # Use the standard port for this server ID
                port = 50050 + i
                self.servers[server_id] = ServerConfig(server_id, server_ip, port)
                
        # Override timeouts if provided
        if os.getenv("ELECTION_TIMEOUT_MIN"):
            self.election_timeout_min = int(os.getenv("ELECTION_TIMEOUT_MIN"))
        if os.getenv("ELECTION_TIMEOUT_MAX"):
            self.election_timeout_max = int(os.getenv("ELECTION_TIMEOUT_MAX"))
        if os.getenv("HEARTBEAT_INTERVAL"):
            self.heartbeat_interval = int(os.getenv("HEARTBEAT_INTERVAL"))
            
        # Override database directory if provided
        if os.getenv("DB_DIRECTORY"):
            self.db_directory = os.getenv("DB_DIRECTORY")
            
    @property
    def server_list(self) -> List[ServerConfig]:
        return list(self.servers.values())
        
    def get_server(self, server_id: str) -> ServerConfig:
        return self.servers.get(server_id)
        
    def get_db_path(self, server_id: str) -> str:
        """Get the database path for a specific server"""
        return os.path.join(self.db_directory, f"{server_id}.db")
        
    def get_random_server(self) -> ServerConfig:
        """Get a random server from the available servers"""
        if not self.servers:
            return None
        return random.choice(list(self.servers.values()))