FROM ubuntu:22.04 

RUN apt-get update && apt-get install -y g++ clang make binutils autoconf automake \
  autotools-dev libtool pkg-config \
  zlib1g-dev libssl-dev libxml2-dev libev-dev \
  libevent-dev libjansson-dev \
  libc-ares-dev libjemalloc-dev libsystemd-dev \
  ruby-dev bison libelf-dev wget vim python3-pip
RUN pip3 install scapy==2.5.0

RUN wget https://github.com/nghttp2/nghttp2/releases/download/v1.61.0/nghttp2-1.61.0.tar.gz && tar -xzf nghttp2-1.61.0.tar.gz
RUN cd nghttp2-1.61.0 && ./configure --prefix=/usr && make && make install

COPY host.cert /host.cert
COPY host.key /host.key
COPY echo-server.py /echo-server.py
COPY h2proxy.py /h2proxy.py
COPY run.sh /run.sh

ENTRYPOINT (/run.sh) && (python3 /echo-server.py &) && (python3 /h2proxy.py 9090 localhost 3000 &) && (tail -f /dev/null)

