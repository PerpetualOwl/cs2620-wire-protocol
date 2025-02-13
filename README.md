# CS2620 Wire Protocol

## Running Instructions

1. Ensure a recent version of python is installed. Install venv on the system as well (in most default installations).

2. Copy sample.env to .env and fill in the desired parameters:
    SERVER_IP: Either 127.0.0.1 to test on your local system. If you are running over a network, make it empty string for the server and the ip address of the server's machine if you are the client.
    SERVER_PORT: Pick any port that isn't taken. Make sure it is the same for the server and client.
    USE_CUSTOM_WIRE_PROTOCOL: True or False whether to use json or a more optimized wire protocol.

3. On the server, run `make server`. On the client run `make client`. If testing on the local machine, run those in different shell sessions.

## Unit/Integration/Regression Testing

All testing code is contained within `test.py` and running make test will show the result of the full testing suite.

## Documentation

General documentation is contained within `docs.md`.

The engineering notebook is contained within `notebook.md`.



