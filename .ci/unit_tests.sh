#!/bin/bash

FILES=$(find . -maxdepth 1 -type d -not -path "./internal_deps*")
nosetests --with-xunit --with-coverage --cover-erase --cover-xml --cover-package=. ${FILES} || exit 1
