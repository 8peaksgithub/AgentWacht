# MCP Shield — Makefile

.PHONY: help install test run dev docker-build docker-run docker-stop docker-logs clean health

help:
	@echo "MCP Shield — Available Commands:"
	@echo ""
	@echo "  make install       Install Python dependencies"
	@echo "  make test          Run test suite"
	@echo "  make run           Start gateway locally"
	@echo "  make dev           Start in development mode (auto-reload)"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Run gateway in Docker"
	@echo "  make docker-stop   Stop Docker container"
	@echo "  make docker-logs   View container logs"
	@echo "  make clean         Remove temporary files and logs"
	@echo "  make health        Check gateway health"
	@echo ""

install:
	pip install -r requirements.txt

test:
	python test_gateway.py

run:
	python run_gateway.py

dev:
	python run_gateway.py --reload --log-level debug

docker-build:
	docker build -t mcp-shield:latest .

docker-run:
	docker compose up -d

docker-stop:
	docker compose down

docker-logs:
	docker compose logs -f gateway

clean:
	rm -rf __pycache__ .pytest_cache *.pyc logs/*.jsonl

health:
	@curl -s http://localhost:8000/health | python -m json.tool
