#!/bin/sh

traefik --configfile /etc/traefik.yaml &
echo $! > /proxy_pid
