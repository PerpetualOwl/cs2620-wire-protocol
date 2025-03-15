# Replicated Chat System

A fault-tolerant chat application that uses the Raft consensus algorithm for replication and SQLite for persistence.

## Features

- **Persistence**: All messages and user data are stored in SQLite databases
- **2-Fault Tolerance**: System continues working with up to 2 server failures
- **Cross-Machine Support**: Can run servers on different machines
- **Automatic Leader Election**: Uses Raft consensus for leader election
- **Automatic Recovery**: Servers can recover state after crashes
- **Client Failover**: Clients automatically reconnect to available servers

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

### Local Testing (Single Machine)

1. Start three server instances:
   ```bash
   # Terminal 1
   python server.py server1

   # Terminal 2
   python server.py server2

   # Terminal 3
   python server.py server3
   ```

2. Start the client:
   ```bash
   python client.py
   ```

### Multi-Machine Deployment

1. Create a configuration file (e.g., `config.env`) on each machine:
   ```bash
   # Example for a three-node cluster
   CHAT_SERVERS=server1:192.168.1.10:50051,server2:192.168.1.11:50051,server3:192.168.1.12:50051
   ```

2. Start servers on each machine:
   ```bash
   # On machine 1
   python server.py server1 config.env

   # On machine 2
   python server.py server2 config.env

   # On machine 3
   python server.py server3 config.env
   ```

3. Start clients on any machine:
   ```bash
   python client.py config.env
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

The system can tolerate up to 2 server failures while maintaining:
- Data consistency
- Service availability
- Message delivery

## Demo Instructions

To demonstrate fault tolerance:

1. Start all three servers
2. Create some user accounts and send messages
3. Kill one or two servers
4. Observe that the system continues to work
5. Restart the failed servers
6. Verify that they recover and sync their state

## Limitations

- Maximum of 2 simultaneous server failures
- Brief service interruption during leader election
- Requires majority of servers to be available

## Future Improvements

- [ ] Dynamic membership changes
- [ ] Better conflict resolution
- [ ] Optimized state transfer
- [ ] Snapshot support
- [ ] Read-only queries from followers