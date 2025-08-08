#!/bin/sh

/usr/local/bin/envoy --concurrency 1 --config-path /etc/envoy/envoy.yaml &
echo $! > /proxy_pid
