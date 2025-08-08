#!/bin/bash

/usr/sbin/varnishd -p feature=+http2 -a :80 -a 127.0.0.1:6086,PROXY -T localhost:6082 -f /etc/varnish/default.vcl
echo `pgrep varnish` > /proxy_pid
/etc/init.d/hitch restart
