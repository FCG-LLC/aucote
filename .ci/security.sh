#!/bin/bash

PYLINT_FILES=$(find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*")

bandit ${PYLINT_FILES} | tee bandit.txt
exit ${PIPESTATUS[0]}