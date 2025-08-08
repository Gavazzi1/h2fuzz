FROM caddy:2.7.6

RUN apk update
RUN apk add vim 
RUN apk add less 
RUN apk add python3 
RUN apk add procps 
RUN apk add curl 
RUN apk add net-tools 
RUN apk add netcat-openbsd 
RUN apk add ngrep 
RUN apk add py3-pip
RUN pip3 install scapy

COPY default.conf /etc/caddy/Caddyfile
COPY echo-server.py /echo-server.py 
COPY h2proxy.py /h2proxy.py
COPY fullchain.pem /etc/letsencrypt/live/smugglingfuzzer.com/fullchain.pem
COPY privkey.pem /etc/letsencrypt/live/smugglingfuzzer.com/privkey.pem
COPY run.sh /run.sh

ENV EXITPORT=8080
ENV EXITHOST=127.0.0.1
ENTRYPOINT (sed -i "s/8080/${EXITPORT}/g" /etc/caddy/Caddyfile) && (sed -i "s/127.0.0.1/${EXITHOST}/g" /etc/caddy/Caddyfile) && (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && (ngrep -t -W single -d any '.' dst port 80 >> /logs/caddy.logs &) && tail -f /dev/null
