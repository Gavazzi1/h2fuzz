#!/bin/bash

/bin/sh -c ldconfig
/usr/local/bin/trafficserver restart
echo "4194305" > /proxy_pid
