#!/bin/sh

h2o --conf /home/h2o/h2o.conf &
echo $! > /proxy_pid
