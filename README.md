# Replicated Chat System

A fault-tolerant chat application that uses the Raft consensus algorithm for replication and SQLite for persistence.

## Features

- **Persistence**: All messages and user data are stored in SQLite databases
- **Multi-Server Support**: Can run up to 5 servers simultaneously
- **Distributed Deployment**: Servers can run on different machines with configurable IP addresses
- **Fault Tolerance**: System continues working with server failures (N-1)/2 fault tolerance with N servers
- **Automatic Leader Election**: Uses Raft consensus for leader election
- **Automatic Recovery**: Servers can recover state after crashes
- **Smart Client Failover**: Clients automatically connect to a random server and failover to others if needed

## Requirements

- Python 3.8+
- Dependencies listed in requirements.txt

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/replicated-chat.git
   cd replicated-chat
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Generate gRPC code:
   ```bash
   python generate_grpc.py
   ```

## Running the System

### Using the Makefile

The system includes a Makefile with various targets for easy management:

```bash
# Set up the environment and dependencies
make setup

# Generate gRPC code
make generate

# Run a specific number of servers (1-5)
make run-servers-1  # Run 1 server
make run-servers-3  # Run 3 servers
make run-servers-5  # Run all 5 servers

# Run individual servers
make run-server1
make run-server2
# ... and so on

# Run a client
make run-client

# Run all servers and a client
make run-all
```

### Local Testing (Single Machine)

1. Configure the `.env` file (copy from `.env.example` if needed):
   ```bash
   # For local testing, use localhost/127.0.0.1
   SERVER1_IP=127.0.0.1
   SERVER2_IP=127.0.0.1
   SERVER3_IP=127.0.0.1
   SERVER4_IP=127.0.0.1
   SERVER5_IP=127.0.0.1
   ```

2. Start any number of servers (1-5):
   ```bash
   # Using make
   make run-servers-3  # Starts 3 servers
   
   # Or manually
   python server.py server1
   python server.py server2
   python server.py server3
   ```

3. Start the client:
   ```bash
   python client.py
   ```

### Multi-Machine Deployment

1. Create/update the `.env` file on all machines with the actual IP addresses:
   ```bash
   # Example for a five-node cluster spread across machines
   SERVER1_IP=192.168.1.10
   SERVER2_IP=192.168.1.10
   SERVER3_IP=192.168.1.11
   SERVER4_IP=192.168.1.12
   SERVER5_IP=192.168.1.12
   ```

2. Start each server on its respective machine:
   ```bash
   # On the machine with IP 192.168.1.10
   python server.py server1  # Starts server1
   python server.py server2  # Starts server2
   
   # On the machine with IP 192.168.1.11
   python server.py server3  # Starts server3
   
   # On the machine with IP 192.168.1.12
   python server.py server4  # Starts server4
   python server.py server5  # Starts server5
   ```

3. Start clients on any machine:
   ```bash
   python client.py  # Client will automatically connect to a random available server
   ```

## Testing

Run the test suite:
```bash
python -m pytest test.py
```

## Architecture

### Server Components

1. **Chat Service**: Handles client requests for chat operations
2. **Raft Consensus**: Manages server replication and leader election
3. **Persistent Storage**: SQLite database for durable storage

### Client Components

1. **Chat Client**: Handles communication with servers
2. **GUI**: PyQt5-based user interface
3. **Automatic Failover**: Reconnects to available servers on failure

### Replication Protocol

The system uses the Raft consensus algorithm for:
- Leader election
- Log replication
- Configuration changes

### Data Persistence

Each server maintains its own SQLite database with tables for:
- Users
- Messages
- Sessions
- Raft state
- Raft log

## Fault Tolerance

The system uses the Raft consensus algorithm for fault tolerance:
- With 3 servers: can tolerate 1 server failure
- With 5 servers: can tolerate 2 server failures
- With a single server: operates in standalone mode

While servers are down, the system maintains:
- Data consistency
- Service availability
- Message delivery

Clients automatically connect to available servers if their current server becomes unavailable.

## Demo Instructions

To demonstrate fault tolerance:

1. Start all three servers
2. Create some user accounts and send messages
3. Kill one or two servers
4. Observe that the system continues to work
5. Restart the failed servers
6. Verify that they recover and sync their state

## Limitations

- Requires a majority of servers to be available (N/2+1 where N is the total number of servers)
- Brief service interruption during leader election
- All servers must share the same `.env` configuration
- Server IDs (server1, server2, etc.) must match their corresponding IP addresses in the `.env` file

## Future Improvements

- [ ] Dynamic membership changes
- [ ] Better conflict resolution
- [ ] Optimized state transfer
- [ ] Snapshot support
- [ ] Read-only queries from followers
- [ ] Secure communication with TLS/SSL
- [ ] Automated deployment with Docker/Kubernetes
- [ ] Load balancing for client connections