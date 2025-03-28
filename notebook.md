# Engineering Notebook

## 2/5/25

### Update 1
Made the repo and makefile along with basic structural planning.

I think we want to do client and server in separate files that run on separate terminals and some shared utils for example which contain functions for serializing and deserializing the wire protocol and potentially encryption of some type maybe to protect passwords.

I think maybe for passwords, there can be a hasing function that is globally shared. Then the client hashes the password, then uses the server's public key which is constantly always available (maybe the client can request a public key packet by sending a packet down the socket). Then the server can decrypt the hash and get a "value" to save for the password.

Not going to bother with a database, since it doesn't have to persist, we can just use an in-memory storage to store everything.

Use a giant lock on the "storage" structure to enforce concurrency. We'll use python threading to accept multiple client connections at the same time (there are also locks/mutexes in this library). 

### Update 2
Just wrote a bunch of helper functions in utils

### Update 3
Started working on client. so the way it handles stuff
1. it constantly waits for inputs from users. When it receives a command, it does the requested action by the user and sends off a packet to the server
2. it constantly waits for packets from the server

## 2/9/25

Fixed lots of messaging related bugs and ironed out the packet passing models.

going to add unit tests next

added some unit tests for everything in utils

### Update 2

wrote a pyqt5 frontend since tkinter was complaining about my macos version
has most of the functionality but one or two (deleting messages and self-message propagation still aren't working as well as I would hope)
Otherwise, it looks pretty good though

Modified makefile to make running all of the commands more easy and also added a way to run the tests

## 2/10/25
Custom Wire Protocol Documentation

Overview:
  The custom wire protocol is designed for efficient, low‐overhead message transmission.
  Each packet is composed of a 1‑byte header carrying the “packet type” (represented as a small integer)
  and a “data” section that contains the packet’s payload encoded in a binary, Type‐Length‐Value (TLV) format.

Overall Packet Format:
  • 1 byte – Packet Type Code
      This code (an unsigned byte) is obtained via a mapping from the MessageType (an enum)
      to an integer (for example, 0 for “request_public_key”, 1 for “public_key_response”, etc.).
      
  • Data Section – A TLV-encoded dictionary:
      The data is encoded as follows:
        – 1 byte: Number of key/value pairs in the dictionary.
        – For each key/value pair:
             • Key:
                 – 1 byte: Key length (unsigned byte). (Assumes key length less than 256.)
                 – N bytes: UTF‑8 encoded key string.
             • Value:
                 • 1 byte: Type tag (identifies the value’s type):
                        1 = String
                        2 = Boolean
                        3 = Integer
                        4 = Float (double precision)
                        5 = Dictionary (recursively encoded, same TLV rules)
                        6 = List (with one byte for the number of elements, then each element encoded recursively)
                 • Then a length field and the actual data:
                        – For TAG_STRING: 2 bytes (unsigned short in network order) for string length followed by the UTF‑8 string.
                        – For TAG_BOOL: 1 byte (0 = False, 1 = True)
                        – For TAG_INT: 4 bytes (signed integer, big-endian)
                        – For TAG_FLOAT: 8 bytes (IEEE‑754 double, big‑endian)
                        – For TAG_DICT: the dictionary is encoded as described (starting with a 1‑byte field count).
                        – For TAG_LIST: 1 byte length followed by each element’s TLV encoding.
                        
Additional Notes:
  – Datetime values (such as timestamps) are converted to ISO‑8601 strings and encoded as TAG_STRING.
  – This protocol avoids any extraneous delimiters or field names in the wire format; keys are encoded only once
    using a compact length‐prefixed string.
  – In test measurements this binary TLV approach produces significantly fewer bytes per packet than JSON,
    which directly maps to improvements in transmission efficiency and scalability as message volume grows.

### Update 1
Added users list and fixed some bugs regarding message propagation

Fixed encryption and decryption schemes that were bugging in some cases

Added flag and option to use custom wire protocol - need better testing and run experiments.

### Update 2
Continued testing the custom wire protocol with more scenarios to ensure reliability. Encountered a few minor decoding issues caused by incorrectly handling certain data types. Added additional test cases to cover edge cases, and updated encoding and decoding logic to handle such cases more robustly.

Ran some performance experiments to compare the custom protocol against JSON serialization. Measured packet sizes and transmission times for various operations such as user registration, message sending, and message retrieval. Observed significant reductions in packet size and improved speed with the custom protocol, especially for operations involving large payloads like fetching all messages.

### Update 3
Implemented detailed logging on both client and server to trace the flow of data and capture any unexpected behavior. This helps with debugging and ensures that any errors are easily identifiable. Logs include timestamps and are categorized by operation type for clearer organization.

Improved error handling in the client-side logic. Added more informative error messages and user feedback for issues like connection loss or failed packet transmission. Also, updated the client to automatically attempt reconnection if the server is temporarily unavailable.

### Update 4
Ran a thorough code review to identify potential security vulnerabilities or inefficiencies. Improved the hashing process for passwords by adding a salt to the hash. This change increases security by making it more difficult to employ brute force attacks on user passwords stored on the server. Noticed that the threading model in the server might benefit from optimization for scalability. Researched several approaches including the use of asynchronous I/O frameworks and message queues. Decided to keep the current threading model for now but it's good to be aware of future improvements.

## 2/11/25

### Update 1

Continued refining the PyQt5 GUI for the client to enhance user experience. Added visual loading indicators for operations that might take a while and ensured that UI components are updated gracefully without blocking the main event loop.
Faced a deadlock issue in the server when multiple clients attempted simultaneous account creation. Investigated and found that the global lock on user data was held for too long during user account operations. Restructured the code to minimize critical sections and prevent this issue while maintaining data integrity.

### Update 2
Implemented a priority queue for managing incoming client requests on the server. The queue allows for more efficient scheduling of high-priority tasks, such as user logins, compared to lower priority tasks like bulk message retrieval. This should improve perceived responsiveness for end-users.

Experimented with implementing a rate-limiting feature to prevent abuse of the server resources by a single client. Found this to be relatively straightforward using token bucket algorithms, and decided to make it an optional, configurable feature depending on server deployment needs. 
### Update 3
Updated unit tests to achieve greater test coverage, especially for error and edge cases. Created a testing strategy document to guide future contributors on how and what to test, ensuring consistent quality checks across the project.

Prepared project documentation, covering setup instructions, the custom protocol specification, and the encryption methodology employed. Also included some initial user guides for the client-side GUI and command-line interface, to aid first-time users in getting started with the application.


## 2/12/25

fix the read/unread handling, add a pointer for last message where the client was connected

Added README with running detailed instructions, got some good feedback from the demo day with other users and found some bugs.

Verified that running the chat application across devices over network also works, need to make ip empty on server to listen on.

## 2/13/25

# Update 1
Added much more comprehensive testing and more detailed running instructions

Used some tricks to emulate certain networking/socket features for better end-to-end testing

## 2/14/25

# Update 1
Add the ability to narrow list of users down via searching functionality (wildtext filtering).

# Update 2
Let us compare our custom wire protocol to JSON. We will do the same actions on the client for both wire protocols.

Here are packet lengths for our custom protol:
Sending packet to ('127.0.0.1', 52566): MessageType.PUBLIC_KEY_RESPONSE
Packet length is: 467
Sending packet to ('127.0.0.1', 52566): MessageType.CREATE_USER_RESPONSE
Packet length is: 43
Sending packet to ('127.0.0.1', 52566): MessageType.INITIAL_CHATDATA
Packet length is: 77
Sending packet to ('127.0.0.1', 52580): MessageType.PUBLIC_KEY_RESPONSE
Packet length is: 467
Sending packet to ('127.0.0.1', 52566): MessageType.USER_ADDED
Packet length is: 19
Sending packet to ('127.0.0.1', 52580): MessageType.CREATE_USER_RESPONSE
Packet length is: 43
Sending packet to ('127.0.0.1', 52580): MessageType.INITIAL_CHATDATA
Packet length is: 85
Sending packet to ('127.0.0.1', 52580): MessageType.MESSAGE_RECEIVED
Packet length is: 138
Sending packet to ('127.0.0.1', 52566): MessageType.MESSAGE_RECEIVED
Packet length is: 138

Here are packet lengths for JSON:
Sending packet to ('127.0.0.1', 52907): MessageType.PUBLIC_KEY_RESPONSE
Packet length is: 519
Sending packet to ('127.0.0.1', 52907): MessageType.CREATE_USER_RESPONSE
Packet length is: 94
Sending packet to ('127.0.0.1', 52907): MessageType.INITIAL_CHATDATA
Packet length is: 135
Sending packet to ('127.0.0.1', 52918): MessageType.PUBLIC_KEY_RESPONSE
Packet length is: 519
Sending packet to ('127.0.0.1', 52907): MessageType.USER_ADDED
Packet length is: 53
Sending packet to ('127.0.0.1', 52918): MessageType.CREATE_USER_RESPONSE
Packet length is: 94
Sending packet to ('127.0.0.1', 52918): MessageType.INITIAL_CHATDATA
Packet length is: 144
Sending packet to ('127.0.0.1', 52918): MessageType.MESSAGE_RECEIVED
Packet length is: 194
Sending packet to ('127.0.0.1', 52907): MessageType.MESSAGE_RECEIVED
Packet length is: 194

We can see that the custom protocol uses roughly 50 less bytes per package, which is pretty significant if most messages are quite short. Hence, our protocol is more efficient. On the other hand, we can note that our serialization starts with a byte representing packet type, which might not be scalable if more kinds of messages are sent between server and client. Backwards compatibility might be broken if we need another byte to represent packet type.

# Overview

We first thought about what we needed to design, because we figured most of our old code was not compatible with gRPC. We want to implement the following features:

- **Account management:**  
  - Create accounts  
  - Login  
  - Delete accounts

- **Message operations:**  
  - Send messages  
  - Receive messages  
  - Delete messages

- **Real-time messaging:**  
  Utilizes gRPC streaming for bi-directional communication.

- **User listing:**  
  Supports wildcard pattern matching for easy searching.


We investigated how to start a gRPC service. We followed the following steps (this includes planning ahead for UI).

1. **Install Required Packages:**

   ```bash
   pip install grpcio grpcio-tools PyQt5
   ```

2. **Generate gRPC Code:**

   Place `chat.proto` in a `proto` directory, then run:

   ```bash
   mkdir -p proto
   cp chat.proto proto/
   python generate_grpc.py
   ```

   This will generate the files:
   - `chat_pb2.py`
   - `chat_pb2_grpc.py`

3. **File Structure:**

   - `chat.proto`: Protocol Buffer definition for the chat service.
   - `chat_server.py`: Server implementation.
   - `chat_client.py`: PyQt5 client implementation.
   - `generate_grpc.py`: Script to generate gRPC code from the proto file.

### gRPC vs. Custom Wire Protocol/JSON

- **Implementation:**  
  - Having code gen made it a lot easier, as we had to think less about annoying details
  - Server implements the service defined in the proto file, less custom logic to figure out how to serialize/deserialize packets.
  - Reduced work to simply implementing each different request. 
  - Client connects via gRPC stubs.
  - Client needs to think a lot less about serialize/deserialize. We also noticed that integration was seemless (it feels like we are making local call). 
  - Client code feels like it does no distributed computing!
  - Sockets have some max bytes they can receive, which is abstracted away with gRPC. 
  - Native support for bi-directional streaming.
  - Overall, gRPC felt much easier on both the server and client side. 

- **Data Size & Performance:**  
  - Binary Protocol Buffers are smaller and faster to serialize/deserialize compared to JSON.
  - Built-in support for streaming.

- **Error Handling:**  
  - gRPC provides built-in status codes and error handling mechanisms.
  - We don't need to think about error handling as much
---

## 2/26/25

### Update 1

- Integrated gRPC by replacing our previous socket-based calls.
- Separated login and account creation into distinct requests.
- Added a streaming endpoint for real-time message delivery when users are online.
- Overall, the gRPC-based request-response structure mirrors the previous design with improvements in performance and reliability.

### Update 2

- Improved the user interface with a new subway surfers–inspired background to aid user focus.

### Update 3

- Fixed several UI bugs:
  - Resolved issues with login failures.
  - Modified the getMessage functionality to trigger on user request rather than automatically.

### Update 4

- Added tests in `test.py` covering:
  - Basic functionality of the chat service.
  - Message operation tests.
  - Integration tests including login functionality.

## Answer to questions.
We answered how client and server implementation changed earlier. Overall gRPC made both much easier. Regarding testing, that was also easier because of the simplification of client and server code. Both followed simpler abstractions that made it easy to test functionality. 

Since some code was rewritten, we can only compare certain requests to old requests with json and the old custom wire protocol. 
Intuitively, it should be smaller because it codegens custom serialization functions for each call.

For the old MESSAGE_RECEIVED response, we took 138 bytes in our packet. However, for gRPC, we only needed 54 bytes. It is clearly a lot more efficient. 

Github Link: https://github.com/PerpetualOwl/cs2620-wire-protocol

## 3/26/25

### Update 1: Enhanced Multi-Server Support

We've implemented significant improvements to the distributed architecture of our chat system, enabling it to run efficiently across multiple machines. The key changes include:

1. Configuration System Overhaul:
   - Modified `config.py` to load server IP addresses from environment variables
   - Added support for up to 5 servers with individual IP configuration
   - Implemented a `get_random_server()` method to allow clients to connect to any available server
   - Added dotenv support for easier configuration management

2. Server Enhancements:
   - Updated the `serve()` function in `server.py` to better handle multi-server configurations
   - Improved single-server mode detection and automatic leader election
   - Added automatic data directory creation
   - Enhanced logging for better debugging of distributed setups

3. Client Improvements:
   - Implemented smart server selection that first tries a random server
   - Added robust failover logic to try all available servers if the random one fails
   - Improved error handling and logging for connection issues
   - Added SSL certificate handling for secure connections

4. Makefile Updates:
   - Added targets for running 1-5 servers (`run-servers-1` through `run-servers-5`)
   - Created individual server targets (`run-server1` through `run-server5`)
   - Updated the `run-all` target to include all 5 servers
   - Added better help documentation

5. Environment Configuration:
   - Created a `.env.example` file with placeholders for server IP addresses
   - Configured the system to use `SERVER1_IP` through `SERVER5_IP` variables
   - Made the environment shared across all servers for consistent configuration

These changes significantly improve the system's flexibility for deployment across multiple machines. We can now run anywhere from 1 to 5 servers on different machines, with the client automatically selecting and connecting to an available server. This enhances both scalability and fault tolerance, as the system can now operate with up to 2 server failures in a 5-server configuration.

The implementation follows the Raft consensus algorithm principles, ensuring data consistency across the distributed system. We've also made sure that servers can automatically detect whether they're running in a single-server or multi-server mode and adjust their behavior accordingly.

Next steps could include implementing secure communication with TLS/SSL (we've already added the groundwork with the certifi integration), adding load balancing for client connections, and creating automated deployment scripts for easier management of the distributed system.