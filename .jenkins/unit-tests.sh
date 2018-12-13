#!/bin/bash

set -ex

cd $WORKSPACE/source

docker-compose up -d postgres
docker-compose up --build aucote
docker-compose down