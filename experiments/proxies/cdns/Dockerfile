FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install vim python3 procps python3-pip -y
RUN pip3 install scapy==2.5.0

COPY h2proxy.py /h2proxy.py

# you can't reset a CDN, but h2proxy will crash without these
COPY run.sh /run.sh
COPY proxy_pid /proxy_pid

ENV EXITHOST=localhost
ENV EXITPORT=443
ENTRYPOINT (python3 /h2proxy.py 9090 $EXITHOST $EXITPORT &) && tail -f /dev/null
