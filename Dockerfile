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
      clang-3.8 \
      clang \
      git \
      vim \
      make \
      ninja-build \
      cmake \
      autoconf \
      automake \
      locales-all \
      dos2unix \
      rsync \
      tar \
      python \
      libssl-dev \
      valgrind \
      libgtest-dev \
      libconfig++-dev \
  && apt-get clean

# build and install ssdeep for fuzzy hashing
COPY build_ssdeep.sh /build_ssdeep.sh
RUN chmod +x /build_ssdeep.sh
RUN ./build_ssdeep.sh

# build and install google test
WORKDIR /usr/src/gtest
RUN cmake CMakeLists.txt && make && cp *.a /usr/lib
WORKDIR /

COPY fuzzer/ /fuzzer
WORKDIR /fuzzer
RUN cmake . && make h2_fuzz
RUN cd h2_fuzz && make test_proxies_up

ENTRYPOINT tail -f /dev/null
