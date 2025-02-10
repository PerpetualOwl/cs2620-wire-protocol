VENV_DIR = venv
PYTHON = $(VENV_DIR)/bin/python3
PIP = $(VENV_DIR)/bin/pip3
REQUIREMENTS = requirements.txt

server: $(VENV_DIR) $(REQUIREMENTS)
	$(PYTHON) server.py

client: $(VENV_DIR) $(REQUIREMENTS)
	$(PYTHON) client.py

test: $(VENV_DIR) $(REQUIREMENTS)
	$(PYTHON) -m unittest test.py

$(VENV_DIR):
	python3.12 -m venv $(VENV_DIR)

$(REQUIREMENTS): $(VENV_DIR)
	python3.12 -m pip install --upgrade pip
	$(PIP) install -r $(REQUIREMENTS)

run: $(VENV_DIR) $(REQUIREMENTS)
	@if ! (echo "$(n)" | grep -Eq '^[0-9]+$$'); then \
		echo "Error: n must be a positive integer"; exit 1; \
	fi
	@echo "Starting server and $(n) clients..."
	@trap 'kill 0' SIGINT SIGTERM EXIT
	@$(PYTHON) server.py &
	@sleep 2  # Allow server to start
	@for i in $(shell seq 1 $(n)); do \
		echo "Starting client $$i"; \
		$(PYTHON) client.py & \
	done
	@wait

help:
	@echo "Usage:"
	@echo "  make server      - Run the server"
	@echo "  make client      - Run a client"
	@echo "  make test        - Run unit tests"
	@echo "  make run n=<N>   - Run the server and N clients in parallel (N must be a positive integer)"
	@echo "  make help        - Display this help message"

.PHONY: server client test run help

all: help
