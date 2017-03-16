#!/bin/bash -e

echo test123 > /tmp/test123
python3 /var/topdis/topdis.py syncdb

exec "$@"

