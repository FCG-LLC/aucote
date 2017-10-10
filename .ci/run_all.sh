#!/bin/bash

#Prepare envs
SHA=$(git rev-parse HEAD)
GITHUB_TOKEN=263f9ede48d798f8d1f92bbefe34f34064ec6f3f
GITHUB_REPO=https://api.github.com/repos/FCG-LLC/aucote
EXIT_VALUE=0

function set_git_status {
    STATE=$1
    TARGET_URL=$2
    DESCRIPTION=$3
    CONTEXT=$4

    curl -X POST -H "Authorization: token ${GITHUB_TOKEN}" "${GITHUB_REPO}/statuses/${SHA}" -d "{
      \"state\": \"${STATE}\",
      \"target_url\": \"${TARGET_URL}\",
      \"description\": \"${DESCRIPTION}\",
      \"context\": \"${CONTEXT}\"
    }" --silent --show-error || return 1
}

function check_status {
    SCRIPT=$1
    TARGET_URL=$2
    DESCRIPTION=$3
    CONTEXT=$4
    STATUS=success
    RETURN_VALUE=0

    set_git_status pending "${BUILD_URL}" "${DESCRIPTION}" "${CONTEXT}"
    bash $SCRIPT || { RETURN_VALUE=1 STATUS=failure; }
    set_git_status ${STATUS} "${BUILD_URL}" "${DESCRIPTION}" "${CONTEXT}"

    return ${RETURN_VALUE}
}

set_git_status pending "${BUILD_URL}" "Status checks executed" "status checks"

check_status .ci/unit_tests.sh "${BUILD_URL}/testReport/" "Performs unit tests" "unit tests" || { EXIT_VALUE=1; echo "UNIT TESTS FAILED"; }
check_status .ci/security.sh "${BUILD_URL}/console" "Checks code security" "code security" || { EXIT_VALUE=1; echo "SECURITY TESTS FAILED"; }
check_status .ci/pylint.sh "${BUILD_URL}/testReport/" "Checks code quality" "code quality"

set_git_status success "${BUILD_URL}" "Status checks executed" "status checks"

exit ${EXIT_VALUE}