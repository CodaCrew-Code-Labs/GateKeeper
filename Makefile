.PHONY: install update

# Define variables for commands
PYTHON=python3
APP_EXECUTABLE=run.py
APP_NAME=run
HOST=0.0.0.0
PORT=3000
GUNICORN=gunicorn
WORKERS=1

# Use environment variable FLASK_ENV to determine dev or prod mode
FLASK_ENV ?= development  # Default to development if not set

# Installing dependencies
install:
	pip install poetry
	poetry install

# Validate all code quality & linting errors
format:
	poetry run isort .
	poetry run black --line-length 70 .
	poetry run flake8 --ignore=E501,W503

# Run tests
test:
	poetry run pytest -v 

# Check coverage
coverage:
	poetry run pytest -v --cov

# Clean up .pyc files
clean:
	find . -name "*.pyc" -exec rm -f {} \;

# Start Flask app using Gunicorn, adjust for environment
run:
ifeq ($(FLASK_ENV), production)
	@echo "Running in production mode"
	$(GUNICORN) --bind $(HOST):$(PORT) $(APP_NAME):app --workers $(WORKERS)
else
	@echo "Running in development mode"
	$(PYTHON) $(APP_EXECUTABLE)
endif