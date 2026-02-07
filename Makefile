# Passive OSINT Reconnaissance Platform Makefile

.PHONY: install install-dev test lint clean run help

# Default target
all: install

# Install the package
install:
	pip install -r requirements.txt
	python setup.py install

# Install development dependencies
install-dev:
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8 mypy
	python setup.py develop

# Run tests
test:
	python -m pytest tests/ -v --cov=passive_osint

# Run linting
lint:
	flake8 passive_osint/
	black --check passive_osint/
	mypy passive_osint/

# Format code
format:
	black passive_osint/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

# Run the tool
run:
	python -m passive_osint.cli --help

# Build distribution
build:
	python setup.py sdist bdist_wheel

# Install in development mode
dev:
	pip install -e .

# Show help
help:
	@echo "Available targets:"
	@echo "  install      - Install the package"
	@echo "  install-dev  - Install with development dependencies"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Run the CLI tool"
	@echo "  build        - Build distribution"
	@echo "  dev          - Install in development mode"
	@echo "  help         - Show this help"
