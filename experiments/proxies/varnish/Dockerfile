FROM varnish:7.5.0

USER root
RUN apt-get update
RUN apt-get install vim python3 procps python3-pip hitch python3-scapy -y
#RUN pip3 install scapy

COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY default.conf /etc/varnish/default.vcl
COPY info-provided-server.pem /etc/hitch/server.pem
COPY hitch.conf /etc/hitch/

RUN chown _hitch:_hitch /etc/hitch/hitch.conf \
&& chown _hitch:_hitch /etc/hitch/server.pem
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null
