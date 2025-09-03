#!/bin/bash

cd nginx && sudo docker build . -t h2_nginx
cd ../caddy && sudo docker build . -t h2_caddy
cd ../apache && sudo docker build . -t h2_apache
cd ../envoy && sudo docker build . -t h2_envoy
cd ../haproxy && sudo docker build . -t h2_haproxy
cd ../traefik && sudo docker build . -t h2_traefik
cd ../varnish && sudo docker build . -t h2_varnish
cd ../h2o && sudo docker build . -t h2_h2o
cd ../ats && sudo docker build . -t h2_ats
cd ../nghttp2 && sudo docker build . -t h2_nghttp
cd ../openlitespeed && sudo docker build . -t h2_openlitespeed
