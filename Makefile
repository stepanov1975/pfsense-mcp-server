SHELL := /usr/bin/env bash
PYTHON ?= python3
PYLINT_ENV := PYTHONPATH=src

.PHONY: install-dev test lint bandit pip-audit secrets pre-commit verify

install-dev:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYLINT_ENV) $(PYTHON) -m pylint src tests

bandit:
	$(PYTHON) -m bandit --configfile pyproject.toml --recursive src

pip-audit:
	$(PYTHON) -m pip_audit . --strict

secrets:
	$(PYTHON) -m detect_secrets scan --baseline .secrets.baseline --force-use-all-plugins

pre-commit:
	$(PYTHON) -m pre_commit run --all-files

verify: test lint bandit pip-audit secrets
