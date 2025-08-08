FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3 vim curl wget systemctl net-tools python3-pip
RUN pip3 install scapy==2.5.0
RUN wget -O - https://repo.litespeed.sh | bash
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y openlitespeed

COPY host.cert /host.cert
COPY host.key  /host.key
COPY conf.tar.gz /usr/local/lsws

RUN cd /usr/local/lsws && tar -xzf conf.tar.gz

COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && (tail -f /dev/null)
