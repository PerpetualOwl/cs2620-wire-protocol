VENV_DIR = venv
PYTHON = $(VENV_DIR)/bin/python3
PIP = $(VENV_DIR)/bin/pip3
REQUIREMENTS = requirements.txt

server: $(VENV_DIR) $(REQUIREMENTS)
	$(PYTHON) server.py

client: $(VENV_DIR) $(REQUIREMENTS)
	$(PYTHON) client.py

$(VENV_DIR):
	python3 -m venv $(VENV_DIR)

$(REQUIREMENTS): $(VENV_DIR)
	$(PIP) install -r $(REQUIREMENTS)

help:
	@echo "Usage:"
	@echo "  make server   - Run the server"
	@echo "  make client   - Run the client"
	@echo "  make help     - Display this help message"

.PHONY: server client help

all: help