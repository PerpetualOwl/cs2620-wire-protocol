# gRPC Chat Application Documentation

This documentation explains how to set up and use the gRPC-based chat server and its corresponding PyQt5 client. The server implements account management, message handling, and real-time delivery via gRPC streams, while the client provides a GUI for interacting with the service.

## Overview

The chat application is built using gRPC for communication between the server and client. The key components include:

- **Server (server.py):**  
  Implements the chat service with the following gRPC endpoints:
  - **CreateAccount:** Create a new user account.
  - **Login:** Authenticate a user and generate a session token.
  - **ListAccounts:** List registered accounts with pagination and wildcard pattern filtering.
  - **DeleteAccount:** Delete a user account.
  - **SendMessage:** Send a message from one user to another.
  - **GetMessages:** Retrieve queued messages for a user.
  - **DeleteMessages:** Delete specific or all messages for a user.
  - **ReceiveMessages:** Provide a real-time stream for incoming messages.

- **Client (client.py):**  
  A PyQt5-based desktop application that:
  - Connects to the gRPC server.
  - Provides a login dialog with options for account creation.
  - Displays incoming messages and allows the user to send, retrieve, and delete messages.
  - Shows user lists with pagination and search capabilities.
  - Implements a background thread to receive real-time messages from the server.

## Requirements

- **Python 3.9+**
- **gRPC:** `grpcio`, `grpcio-tools`
- **PyQt5:** For the client GUI
- Other standard libraries: `hashlib`, `uuid`, `threading`, etc.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Install Dependencies:**
   ```bash
   pip install grpcio grpcio-tools PyQt5
   ```

3. **Generate gRPC Code:**

   If you have a `chat.proto` file, generate the Python files:
   ```bash
   python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. chat.proto
   ```
   This should create `chat_pb2.py` and `chat_pb2_grpc.py`, which are used by both the server and client.

## Running the Server

1. **Start the Server:**
   ```bash
   python server.py
   ```
2. **Server Details:**
   - Listens on port `50051`.
   - Uses an in-memory store for accounts, messages, and session tokens.
   - Logs events (account creation, login, message delivery, etc.) using Python's `logging` module.
   - Designed for demonstration and testing (for production use, consider integrating a database and robust session management).

## Running the Client

1. **Launch the Client Application:**
   ```bash
   python client.py
   ```
2. **Client Functionality:**
   - **Connection:**  
     Enter the server address (default: `localhost:50051`) and click **Connect**.
   - **Login / Account Creation:**  
     A login dialog appears. Users can log in or choose to create a new account.
   - **Messaging:**  
     Once logged in, users can:
     - View and receive messages in real time.
     - Retrieve queued messages using the **Get Messages** button.
     - Send messages by selecting a recipient and typing a message.
     - Delete selected or all messages.
   - **User List & Search:**  
     Navigate to the **User List** tab to search and browse registered accounts using a pattern match and pagination.
   - **Account Deletion:**  
     Users can delete their account via the **Account** tab, which prompts for password confirmation.

## API Documentation

### 1. Account Management

- **CreateAccount**
  - **Request:** `CreateAccountRequest` with fields: `username`, `password_hash`
  - **Response:** `CreateAccountResponse` with:
    - `success` (bool)
    - `message` (string)
    - `account_exists` (bool)
  - **Description:** Creates a new account. If the account already exists, it advises logging in instead.

- **Login**
  - **Request:** `LoginRequest` with fields: `username`, `password_hash`
  - **Response:** `LoginResponse` with:
    - `success` (bool)
    - `message` (string)
    - `unread_message_count` (int)
    - `session_token` (string)
  - **Description:** Authenticates the user and returns a session token for subsequent requests.

- **DeleteAccount**
  - **Request:** `DeleteAccountRequest` with fields: `username`, `password_hash`, `session_token`
  - **Response:** `DeleteAccountResponse` with:
    - `success` (bool)
    - `message` (string)
  - **Description:** Deletes a user account after verifying the password.

### 2. Messaging

- **SendMessage**
  - **Request:** `SendMessageRequest` with fields: `sender`, `recipient`, `content`, `session_token`
  - **Response:** `SendMessageResponse` with:
    - `success` (bool)
    - `message` (string)
    - `message_id` (string)
  - **Description:** Sends a message. If the recipient is online, the message is delivered immediately via active streams; otherwise, it is queued.

- **GetMessages**
  - **Request:** `GetMessagesRequest` with fields: `username`, `limit`, `session_token`
  - **Response:** `GetMessagesResponse` with:
    - `messages` (repeated Message)
    - `remaining_messages` (int)
  - **Description:** Retrieves a limited number of messages for a user and marks them as read.

- **DeleteMessages**
  - **Request:** `DeleteMessagesRequest` with fields: `username`, `message_ids` (list), `session_token`
  - **Response:** `DeleteMessagesResponse` with:
    - `success` (bool)
    - `message` (string)
    - `deleted_count` (int)
  - **Description:** Deletes selected messages (or all messages if all IDs are provided) for the user.

- **ReceiveMessages**
  - **Request:** `ReceiveMessagesRequest` with fields: `username`, `session_token`
  - **Response:** Streams of `Message` objects.
  - **Description:** Provides a streaming endpoint that delivers real-time messages to the client as they become available.

### 3. Account Listing

- **ListAccounts**
  - **Request:** `ListAccountsRequest` with fields: `pattern`, `page`, `page_size`, `session_token`
  - **Response:** `ListAccountsResponse` with:
    - `usernames` (list of strings)
    - `total_accounts` (int)
    - `current_page` (int)
    - `total_pages` (int)
  - **Description:** Returns a paginated list of user accounts matching the provided wildcard pattern (supports `*` and `?`).

## Notes & Considerations

- **Security:**  
  Passwords are hashed using SHA-256 on the client side before being transmitted. For production, consider using a more robust password hashing algorithm (e.g., bcrypt) and secure transport (TLS).

- **Session Management:**  
  Sessions are stored in an in-memory dictionary. If scaling is required, you may want to store sessions in a persistent store.

- **Concurrency:**  
  The server uses Python threads for handling multiple gRPC calls. Ensure your production environment is configured to handle the desired load.

- **Real-Time Messaging:**  
  The `ReceiveMessages` endpoint uses a simple polling mechanism (with a sleep interval) to yield new messages. This could be optimized using more advanced async patterns if needed.

- **GUI Customization:**  
  The client uses PyQt5 for the user interface. Customize the look and feel (e.g., background image, layouts) as per your branding or design requirements.
