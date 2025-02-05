# Engineering Notebook

### 2/5/25
Made the repo and makefile along with basic structural planning.

I think we want to do client and server in separate files that run on separate terminals and some shared utils for example which contain functions for serializing and deserializing the wire protocol and potentially encryption of some type maybe to protect passwords.

I think maybe for passwords, there can be a hasing function that is globally shared. Then the client hashes the password, then uses the server's public key which is constantly always available (maybe the client can request a public key packet by sending a packet down the socket). Then the server can decrypt the hash and get a "value" to save for the password.

Not going to bother with a database, since it doesn't have to persist, we can just use an in-memory storage to store everything.

Use a giant lock on the "storage" structure to enforce concurrency. We'll use python threading to accept multiple client connections at the same time (there are also locks/mutexes in this library). 

