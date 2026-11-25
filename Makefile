.PHONY: install test lint eval serve
install:
	pip install -e ".[dev]"
test:
	pytest
lint:
	ruff check src tests
eval:
	agentguard eval
serve:
	agentguard serve --port 8000
