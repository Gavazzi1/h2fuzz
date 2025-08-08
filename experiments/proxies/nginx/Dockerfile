FROM nginx:1.25.4

RUN apt-get update
RUN apt-get install vim python3 procps python3-pip python3-scapy -y
#RUN pip3 install scapy

COPY default.conf /etc/nginx/conf.d/default.conf
COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY localcerts/server.cert /etc/nginx/server.cert
COPY localcerts/server.key /etc/nginx/server.key

COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null
