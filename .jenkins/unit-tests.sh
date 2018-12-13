#!/bin/bash

set -ex

cd $WORKSPACE/source

docker-compose up -d postgres
docker-compose up --build aucote
RESULT=$?
docker-compose down

exit $RESULT