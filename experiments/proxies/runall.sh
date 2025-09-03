#!/bin/bash

sudo docker run -d --rm h2_nginx
sudo docker run -d --rm h2_caddy
sudo docker run -d --rm h2_apache
sudo docker run -d --rm h2_envoy
sudo docker run -d --rm h2_haproxy
sudo docker run -d --rm h2_traefik
sudo docker run -d --rm h2_varnish
sudo docker run -d --rm h2_h2o
sudo docker run -d --rm h2_ats
sudo docker run -d --rm h2_nghttp
sudo docker run -d --rm h2_openlitespeed
