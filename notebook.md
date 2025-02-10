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