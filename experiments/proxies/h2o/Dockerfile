FROM lkwg82/h2o-http2-server:v2.2.6

USER root
RUN apk update
RUN apk add vim
RUN apk add python3
RUN apk add procps
RUN apk add py3-pip
RUN pip3 install scapy

COPY echo-server.py /echo-server.py 
COPY h2proxy.py /h2proxy.py
COPY h2o.conf /home/h2o/h2o.conf
COPY localcerts/server.cert /server.cert
COPY localcerts/server.key  /server.key
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null 
#ENTRYPOINT tail -f /dev/null
