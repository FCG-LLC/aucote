#!/usr/bin/env bash

ports="U:0-65535,T:0-65535"

for network_rate in {500..10000..500}
do
    for port_rate in {20..100..20}
    do
        for tool_rate in {20..100..20}
        do
            for threads in {5..40..5}
            do
                echo "start: $(date +%s):$(date)"
                echo "Execute aucote with:
network-rate: ${network_rate}
port-rate: ${port_rate}
tool-rate: ${tool_rate}
ports: ${ports}
threads: ${threads}
toucan-host: ${1:-toucan}"
                bash stress_scan.sh ${network_rate} ${port_rate} ${tool_rate} ${ports} ${threads} ${1:-http://toucan:3000}
                echo "end: $(date +%s):$(date)"
                echo "Sleeping for ${2:-120}"
                sleep ${2:-120}
            done
        done
    done
done