FROM ubuntu:16.04

RUN DEBIAN_FRONTEND="noninteractive" apt-get update && apt-get -y install tzdata

# probably don't need all of these, but it's what the online tutorial had
# new ones are: clang-3.8, git, vim, and libssl-dev
RUN apt-get update \
  && apt-get install -y ssh \
      build-essential \
      gcc \
      g++ \
      gdb \
      git \
      clang-3.8 \
      clang \
      vim \
      make \
      ninja-build \
      cmake \
      autoconf \
      automake \
      locales-all \
      rsync \
      tar \
      python \
      libssl-dev \
      libgtest-dev \
      libconfig++-dev \
  && apt-get clean

# build and install ssdeep for fuzzy hashing
RUN git clone https://github.com/DinoTools/python-ssdeep.git
WORKDIR python-ssdeep
RUN git checkout 9ca00aa37f1ca4c2dcb12978ef61fa8d12186ca7
WORKDIR ssdeep-lib/
RUN ./configure --prefix=`pwd`/../../../../builds/libs/ssdeep-lib CC=clang CXX=clang++ && \
    make && make install

# build and install google test
WORKDIR /usr/src/gtest
RUN cmake CMakeLists.txt && make && cp *.a /usr/lib
WORKDIR /

COPY fuzzer/ /fuzzer
WORKDIR /fuzzer
RUN cmake . && make h2_fuzz
RUN cd h2_fuzz && make test_proxies_up

ENTRYPOINT tail -f /dev/null
