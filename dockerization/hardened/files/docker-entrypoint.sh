#!/bin/bash

export python="python3"

cd /opt/aucote

set -x
exec gosu aucote /opt/aucote/venv/bin/python aucote.py --syncdb
