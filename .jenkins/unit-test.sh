#!/bin/bash

docker build -t cs/aucote .
docker run --rm -P -v `pwd`:`pwd` -w=`pwd`/source cs/aucote pylint --max-line-length=120 -f parseable $(cd source && find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*") | tee pylint.out
docker run --rm -P -v `pwd`:`pwd` -w=`pwd`/source cs/aucote nosetests --with-xunit --with-coverage --cover-erase --cover-xml --cover-package=. $(cd source && find . -maxdepth 1 -type d)
