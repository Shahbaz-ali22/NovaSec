#!/bin/bash
poetry run ruff check novasec/ && poetry run mypy novasec/
