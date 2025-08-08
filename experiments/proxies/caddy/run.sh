#!/bin/sh

caddy stop
caddy start --config /etc/caddy/Caddyfile & 
echo "4194305" > /proxy_pid
