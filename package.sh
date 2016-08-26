#! /bin/bash

set -e

VERSION=$1
PACKAGE_NAME=aucote
PYTHON_FILES=`find . -not -path './venv*' -and -not -path './package*' -and -name '*.py'`
PACKAGE_FILES="venv ${PYTHON_FILES} fixtures/exploits/* static/* aucote_cfg.yaml.example"
PACKAGE_PATH=package/${PACKAGE_NAME}_${VERSION}
PACKAGE_TARGET_PATH=${PACKAGE_PATH}/opt/${PACKAGE_NAME}
PACKAGE_BIN_PATH=${PACKAGE_PATH}/bin/
PACKAGE_START_SCRIPTS=start_scripts/*
PYTHON_VERSION=python3
DEPENDENCIES="python3 (>= 3.4), nanomsg, libpq5, libyaml-dev, nmap, hydra (>= 8.3)"

[[ -z $VERSION ]] && { echo "Usage: package [version]"; exit 1; }

virtualenv --python=${PYTHON_VERSION} --always-copy venv
source venv/bin/activate
easy_install -U setuptools
pip install -r requirements.txt

rm -rf ${PACKAGE_PATH}
mkdir -p ${PACKAGE_PATH}
mkdir -p ${PACKAGE_TARGET_PATH}
mkdir -p ${PACKAGE_PATH}/DEBIAN
mkdir -p ${PACKAGE_PATH}/bin

cat >${PACKAGE_PATH}/DEBIAN/control <<EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: base
Priority: optional
Architecture: all
Depends: ${DEPENDENCIES}
Maintainer: Szymon Wieloch <simon@collective-sense.com>
Description: Component for network topology discovery

EOF

cp -r --parents ${PACKAGE_FILES} ${PACKAGE_TARGET_PATH}
cp ${PACKAGE_START_SCRIPTS} ${PACKAGE_BIN_PATH}
dpkg-deb --build ${PACKAGE_PATH}
