FROM haproxy:3.0-dev

USER root
RUN apt-get update
RUN apt-get install vim python3 procps python3-pip python3-scapy -y
#RUN pip3 install scapy

COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY default.conf /usr/local/etc/haproxy/haproxy.cfg
COPY server.pem /usr/local/etc/haproxy/server.pem
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null
