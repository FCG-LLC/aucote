#!/bin/bash

PYLINT_FILES=$(find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*" -not -path "./internal_deps*")

bandit -ll ${PYLINT_FILES} | tee bandit.txt
exit ${PIPESTATUS[0]}