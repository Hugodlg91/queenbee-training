.PHONY: lint types test security arch check
lint:      ; ruff check . && ruff format --check .
types:     ; mypy
test:      ; python -m pytest --cov=src/queenbee --cov-fail-under=90
security:  ; bandit -q -r src -c pyproject.toml && pip-audit
arch:      ; PYTHONPATH=src lint-imports
check: lint types test security arch
