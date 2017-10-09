#!/bin/bash

set -ex

cd $WORKSPACE/source

docker build --build-arg destEnv=$destEnv -t cs/aucote .
docker run --rm -P -v `pwd`:`pwd` -w=`pwd` -e BUILD_URL cs/aucote bash .ci/run_all.sh
