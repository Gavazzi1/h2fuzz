#!/bin/bash

haproxy -f /usr/local/etc/haproxy/haproxy.cfg &
echo $! > /proxy_pid
