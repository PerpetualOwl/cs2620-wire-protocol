VENV_DIR = venv
PYTHON = $(VENV_DIR)/bin/python3
PIP = $(VENV_DIR)/bin/pip3
REQUIREMENTS_FILE = requirements.txt

.PHONY: all venv install-deps server client test help clean

all: help

# Create the virtual environment if it doesn’t already exist.
venv:
	@test -d $(VENV_DIR) || python3.12 -m venv $(VENV_DIR)

# Always install (or upgrade) pip and install the required packages.
install-deps: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r $(REQUIREMENTS_FILE)

server: install-deps
	$(PYTHON) server.py

client: install-deps
	$(PYTHON) client.py

test: install-deps
	$(PYTHON) -m unittest test.py

help:
	@echo "Usage:"
	@echo "  make server      - Run the server"
	@echo "  make client      - Run a client"
	@echo "  make test        - Run unit tests"
	@echo "  make clean       - Remove the virtual environment"
	@echo "  make help        - Display this help message"

clean:
	rm -rf $(VENV_DIR)