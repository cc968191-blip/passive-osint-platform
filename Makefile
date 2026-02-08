.PHONY: install test clean run serve help

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

run:
	python -m passive_osint.cli --help

serve:
	python app.py

help:
	@echo "  install  Install dependencies"
	@echo "  test     Run test suite"
	@echo "  clean    Remove build artifacts"
	@echo "  run      Show CLI usage"
	@echo "  serve    Start web server"
	@echo "  help     Show this help"
