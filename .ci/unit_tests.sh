#!/bin/bash

FILES=$(find . -maxdepth 1 -type d -not -path "./internal_deps*")
python -m nose --with-xunit --with-coverage --cover-erase --cover-xml --cover-package=. ${FILES} || exit 1
