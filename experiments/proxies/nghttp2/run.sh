#!/bin/bash

nghttpx -b'127.0.0.1,8080' /host.key /host.cert &
echo $! > /proxy_pid
