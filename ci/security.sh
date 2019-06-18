#!/bin/bash

PYLINT_FILES=$(find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*" -not -path "./internal_deps*")

python -m bandit -ll ${PYLINT_FILES} | tee /tmp/bandit.txt
exit ${PIPESTATUS[0]}