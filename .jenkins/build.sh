#!/bin/bash

set -ex

exec $WORKSPACE/source/.ci-utils/entrypoint.sh build
