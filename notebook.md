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