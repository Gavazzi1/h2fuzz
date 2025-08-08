FROM traefik:3.0

RUN apk update
RUN apk add vim
RUN apk add python3
RUN apk add procps
RUN apk add py3-pip
#RUN apk add py3-scapy
RUN pip3 install --break-system-packages scapy

RUN mkdir /etc/certs && mkdir /etc/confs

COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py

COPY traefik.yaml /etc/traefik.yaml 
COPY main.yaml /etc/confs/ 
COPY tls.yaml /etc/confs/ 
COPY host.key /etc/certs/
COPY host.cert /etc/certs/
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null
