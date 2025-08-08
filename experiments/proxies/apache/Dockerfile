FROM httpd:2.4.58

RUN apt update -y
RUN apt-get install vim python3 procps python3-pip python3-scapy -y
#RUN pip3 install scapy

COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY localcerts/server.cert /usr/local/apache2/localhost.crt
COPY localcerts/server.key /usr/local/apache2/localhost.key
COPY default.conf /usr/local/apache2/conf/extra/000-default.conf

#RUN sed -i '/mod_proxy.so/s/^#//' /usr/local/apache2/conf/httpd.conf \
#&& sed -i '/mod_proxy_http.so/s/^#//' /usr/local/apache2/conf/httpd.conf \
#&& sed -i '/mod_http2.so/s/^#//' /usr/local/apache2/conf/httpd.conf \
#&& sed -i '/mod_ssl.so/s/^#//' /usr/local/apache2/conf/httpd.conf \
#&& sed -i 's/Listen 80/Listen 443/' /usr/local/apache2/conf/httpd.conf \
#&& sed -i 's/^LogLevel.*/LogLevel Debug/' /usr/local/apache2/conf/httpd.conf \
#&& echo "Include conf/extra/000-default.conf" >> /usr/local/apache2/conf/httpd.conf

COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 443 &) && (tail -f /dev/null)
