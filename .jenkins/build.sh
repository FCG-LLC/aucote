#!/bin/bash

set -ex

$WORKSPACE/source/.ci/gitlab/build.sh
exec $WORKSPACE/source/.ci-utils/entrypoint.sh build
