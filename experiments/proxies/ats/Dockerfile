FROM ubuntu:22.04
RUN apt update -y

RUN apt install vim curl less net-tools netcat python3 -y

RUN export DEBIAN_FRONTEND=noninteractive
RUN truncate -s0 /tmp/preseed.cfg; \
    echo "tzdata tzdata/Areas select Europe" >> /tmp/preseed.cfg; \
    echo "tzdata tzdata/Zones/Europe select Berlin" >> /tmp/preseed.cfg; \
    debconf-set-selections /tmp/preseed.cfg && \
    rm -f /etc/timezone /etc/localtime && \
    apt install -y tzdata

RUN apt install -y autoconf automake libtool pkg-config libmodule-install-perl gcc libssl-dev libpcre3-dev libcap-dev libhwloc-dev libncurses5-dev libcurl4-openssl-dev flex g++ tk-dev tcl-dev make

RUN curl -O https://downloads.apache.org/trafficserver/trafficserver-9.2.4.tar.bz2
RUN tar xf trafficserver-9.2.4.tar.bz2
RUN cd trafficserver-9.2.4 && ./configure && make -j8 && make install

RUN export LD_LIBRARY_PATH=/usr/local/lib/

####################
### Above this line just installs ats, and used to be its own Docker image
####################

RUN apt update -y
RUN apt-get install vim python3 procps python3-pip -y
RUN pip3 install scapy

RUN sed -i '/CONFIG proxy.config.http.server_ports/s/.*/CONFIG proxy.config.http.server_ports STRING 443:ssl/' /usr/local/etc/trafficserver/records.config \
&& sed -i '/CONFIG proxy.config.url_remap.pristine_host_hdr/s/.*/CONFIG proxy.config.url_remap.pristine_host_hdr INT 1/' /usr/local/etc/trafficserver/records.config \
&& echo "CONFIG proxy.config.ssl.server.cert.path STRING /usr/local/etc/trafficserver/certs\nCONFIG proxy.config.ssl.server.private_key.path STRING /usr/local/etc/trafficserver/keys\nCONFIG proxy.config.ssl.client.verify.server INT 0\nCONFIG proxy.config.ssl.client.CA.cert.filename STRING NULL" >> /usr/local/etc/trafficserver/records.config 

RUN echo "dest_ip=* ssl_cert_name=host.pem" > /usr/local/etc/trafficserver/ssl_multicert.config

RUN mkdir /usr/local/etc/trafficserver/certs \
&& mkdir /usr/local/etc/trafficserver/keys

COPY server.key /usr/local/etc/trafficserver/keys/host.key
COPY server.pem /usr/local/etc/trafficserver/certs/host.pem

RUN chown nobody:nogroup /usr/local/etc/trafficserver/keys \
&& chown nobody:nogroup /usr/local/etc/trafficserver/certs \
&& chown nobody:nogroup /usr/local/etc/trafficserver/keys/host.key \
&& chown nobody:nogroup /usr/local/etc/trafficserver/certs/host.pem

RUN echo "map / http://127.0.0.1:8080/" > /usr/local/etc/trafficserver/remap.config
#RUN echo "header_rewrite.so rules.config" > /usr/local/etc/trafficserver/plugin.config \
#&& echo "cond %{SEND_REQUEST_HDR_HOOK}" > /usr/local/etc/trafficserver/rules.config \
#&& echo "add-header x-method %{METHOD}" >> /usr/local/etc/trafficserver/rules.config \
#&& echo "add-header x-uri \"/%{CLIENT-URL:PATH}\"" >> /usr/local/etc/trafficserver/rules.config \
#&& echo "add-header x-query %{CLIENT-URL:QUERY}" >> /usr/local/etc/trafficserver/rules.config \
#&& echo "add-header x-proto %{CLIENT-URL:SCHEME}" >> /usr/local/etc/trafficserver/rules.config \
#&& echo "add-header x-host %{CLIENT-URL:HOST}" >> /usr/local/etc/trafficserver/rules.config \
#&& echo "add-header x-port %{CLIENT-URL:PORT}" >> /usr/local/etc/trafficserver/rules.config

COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && tail -f /dev/null
