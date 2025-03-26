.PHONY: setup clean generate test run-server1 run-server2 run-server3 run-server4 run-server5 run-client run-all run-all-s run-servers-1 run-servers-2 run-servers-3 run-servers-4 run-servers-5

# Variables
PYTHON = python
VENV = venv
VENV_ACTIVATE = $(VENV)/bin/activate
PIP = $(VENV)/bin/pip
PYTHON_VENV = . $(VENV_ACTIVATE) && python

# Default target
all: setup generate

# Setup virtual environment and install dependencies
setup:
	@echo "Setting up virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "Installing dependencies..."
	$(PIP) install -r requirements.txt

# Generate gRPC code
generate:
	@echo "Generating gRPC code..."
	$(PYTHON_VENV) generate_grpc.py

# Clean up generated files and virtual environment
clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf */__pycache__
	rm -f *.db
	rm -f server*.db

# Run tests
test:
	@echo "Running tests..."
	$(PYTHON_VENV) -m pytest test.py

# Run server instances
run-server1:
	@echo "Starting server1..."
	$(PYTHON_VENV) server.py server1

run-server2:
	@echo "Starting server2..."
	$(PYTHON_VENV) server.py server2

run-server3:
	@echo "Starting server3..."
	$(PYTHON_VENV) server.py server3

run-server4:
	@echo "Starting server4..."
	$(PYTHON_VENV) server.py server4

run-server5:
	@echo "Starting server5..."
	$(PYTHON_VENV) server.py server5

# Run client
run-client:
	@echo "Starting client..."
	$(PYTHON_VENV) client.py

# Run specific number of servers in background
run-servers-1:
	@echo "Starting 1 server..."
	$(PYTHON_VENV) server.py server1

run-servers-2:
	@echo "Starting 2 servers..."
	$(PYTHON_VENV) server.py server1 & \
	$(PYTHON_VENV) server.py server2

run-servers-3:
	@echo "Starting 3 servers..."
	$(PYTHON_VENV) server.py server1 & \
	$(PYTHON_VENV) server.py server2 & \
	$(PYTHON_VENV) server.py server3

run-servers-4:
	@echo "Starting 4 servers..."
	$(PYTHON_VENV) server.py server1 & \
	$(PYTHON_VENV) server.py server2 & \
	$(PYTHON_VENV) server.py server3 & \
	$(PYTHON_VENV) server.py server4

run-servers-5:
	@echo "Starting all 5 servers..."
	$(PYTHON_VENV) server.py server1 & \
	$(PYTHON_VENV) server.py server2 & \
	$(PYTHON_VENV) server.py server3 & \
	$(PYTHON_VENV) server.py server4 & \
	$(PYTHON_VENV) server.py server5

# Run all servers in background and client in foreground
run-all:
	@echo "Starting all servers and client..."
	$(PYTHON_VENV) server.py server1 & \
	$(PYTHON_VENV) server.py server2 & \
	$(PYTHON_VENV) server.py server3 & \
	$(PYTHON_VENV) server.py server4 & \
	$(PYTHON_VENV) server.py server5 & \
	$(PYTHON_VENV) client.py

# Alias for run-servers-5
run-all-s: run-servers-5

# Help
help:
	@echo "Available targets:"
	@echo "  make setup      - Set up virtual environment and install dependencies"
	@echo "  make generate   - Generate gRPC code"
	@echo "  make clean      - Clean up generated files and virtual environment"
	@echo "  make test       - Run tests"
	@echo "  make run-server1 - Run server1"
	@echo "  make run-server2 - Run server2"
	@echo "  make run-server3 - Run server3"
	@echo "  make run-server4 - Run server4"
	@echo "  make run-server5 - Run server5"
	@echo "  make run-client - Run client"
	@echo "  make run-servers-1 - Run 1 server"
	@echo "  make run-servers-2 - Run 2 servers"
	@echo "  make run-servers-3 - Run 3 servers"
	@echo "  make run-servers-4 - Run 4 servers"
	@echo "  make run-servers-5 - Run all 5 servers"
	@echo "  make run-all    - Run all servers and client"
	@echo "  make run-all-s  - Run all 5 servers (alias for run-servers-5)"
	@echo "  make help       - Show this help message"
