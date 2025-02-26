# gRPC Chat Application

This is a simple client-server chat application implemented using gRPC and PyQt5. The application allows users to create accounts, send and receive messages, list other users, and manage their account.

## Features

- Account management (create, login, delete)
- Message operations (send, receive, delete)
- Real-time message delivery using gRPC streaming
- User listing with wildcard pattern matching
- Password hashing for security
- PyQt5 graphical interface

## Requirements

- Python 3.6+
- gRPC and gRPC tools
- PyQt5

## Setup

1. Install required Python packages:

```bash
pip install grpcio grpcio-tools PyQt5
```

2. Generate gRPC code from proto file:

```bash
# Place chat.proto in the proto directory
mkdir -p proto
cp chat.proto proto/

# Run the code generator script
python generate_grpc.py
```

This will generate the `chat_pb2.py` and `chat_pb2_grpc.py` files required for the application.

## Running the Application

1. Start the server:

```bash
python chat_server.py
```

The server will start on port 50051 by default.

2. Launch the client:

```bash
python chat_client.py
```

The client will connect to the server on `localhost:50051` by default. You can change this in the client UI.

## File Structure

- `chat.proto`: Protocol Buffer definition for the chat service
- `chat_server.py`: Server implementation
- `chat_client.py`: PyQt5 client implementation
- `generate_grpc.py`: Helper script to generate gRPC code from proto file

## gRPC vs Custom Wire Protocol/JSON

### What has changed?

#### Protocol Definition

- With gRPC, the protocol is defined in a `.proto` file using Protocol Buffers.
- The client and server code is generated from this definition.
- This ensures consistent data structures and prevents errors.

#### Implementation

- The server implements the service defined in the proto file
- The client connects to the server using gRPC stubs
- Streaming is handled natively by gRPC

#### Data Size

gRPC uses Protocol Buffers which is a binary format, rather than JSON or a custom text-based protocol. This results in:
- Smaller message sizes
- Faster serialization/deserialization
- Native support for streaming (used for real-time messages)

#### Error Handling

gRPC provides built-in error handling and status codes, making it easier to handle failures and edge cases.

## Advantages of gRPC

1. **Smaller message size**: Protocol Buffers are more compact than JSON
2. **Type safety**: The protocol definition enforces types
3. **Code generation**: Less boilerplate code needed
4. **Bi-directional streaming**: Built-in support for streaming
5. **HTTP/2**: Better performance with multiplexing and header compression

## Disadvantages

1. **Steeper learning curve**: More complex setup compared to simple sockets
2. **Less human-readable**: Binary format is not human-readable like JSON
3. **Requires code generation**: Changes to the protocol require regeneration of code

## Generating the proto code if you modify chat.proto

```bash
python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. chat.proto
```

to fix
fix deletion ui
fix logout hanging
test load messages after logout
generate unit tests
forge notebook