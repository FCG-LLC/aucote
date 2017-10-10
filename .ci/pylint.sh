#!/bin/bash

PYLINT_FILES=$(find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*") # Files without virtualenv and tests

pylint --max-line-length=120 -f parseable ${PYLINT_FILES} | tee pylint.out