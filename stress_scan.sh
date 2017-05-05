#!/usr/bin/env bash

venv/bin/python stress_scan.py --network-rate=$1 --port-rate=$2 --tool-rate=$3 --ports=$4 --threads=$5 --toucan=$6
venv/bin/python aucote.py scan --cfg stress_scan.yaml >> logs/test.log