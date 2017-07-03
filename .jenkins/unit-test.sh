#!/bin/bash

cd $WORKSPACE/source

docker build -t cs/aucote .
docker run --rm -P -v `pwd`:`pwd` -w=`pwd` cs/aucote pylint --max-line-length=120 -f parseable $(find . -name "*.py" -not -path "./tests/*" -not -path "./venv/*") | tee pylint.out
docker run --rm -P -v `pwd`:`pwd` -w=`pwd` cs/aucote nosetests --with-xunit --with-coverage --cover-erase --cover-xml --cover-package=. $(find . -maxdepth 1 -type d)
