FROM envoyproxy/envoy-alpine:v1.21.6

RUN apk update
RUN apk add vim 
RUN apk add python3
RUN apk add procps
RUN apk add py3-pip
RUN pip3 install scapy

COPY echo-server.py /echo-server.py 
COPY h2proxy.py /h2proxy.py
COPY envoy.yaml /etc/envoy/
COPY host.cert /etc/envoy/host.cert
COPY host.key /etc/envoy/host.key
COPY run.sh /run.sh

ENTRYPOINT (/run.sh &) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null
