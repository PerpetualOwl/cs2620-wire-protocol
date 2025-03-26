.PHONY: setup clean generate test run-server1 run-server2 run-server3 run-client

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

# Run client
run-client:
	@echo "Starting client..."
	$(PYTHON_VENV) client.py

# Run all servers in background and client in foreground
run-all:
	@echo "Starting all servers and client..."
	$(PYTHON_VENV) server.py server1 & \
	$(PYTHON_VENV) server.py server2 & \
	$(PYTHON_VENV) server.py server3 & \
	$(PYTHON_VENV) client.py

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
	@echo "  make run-client - Run client"
	@echo "  make run-all    - Run all servers and client"
	@echo "  make help       - Show this help message"
