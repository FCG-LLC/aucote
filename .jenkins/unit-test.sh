#!/bin/bash

SOURCE_DIR=source
docker build -t cs/aucote .
docker run --rm -P -v `pwd`:`pwd` -w=`pwd`/${SOURCE_DIR} cs/aucote pylint --max-line-length=120 -f parseable $(cd ${SOURCE_DIR} && find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*") | tee pylint.out
docker run --rm -P -v `pwd`:`pwd` -w=`pwd`/${SOURCE_DIR} cs/aucote nosetests --with-xunit --with-coverage --cover-erase --cover-xml --cover-package=. $(cd ${SOURCE_DIR} && find . -maxdepth 1 -type d)
