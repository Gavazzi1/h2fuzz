#!/bin/bash

git clone https://github.com/DinoTools/python-ssdeep.git
cd python-ssdeep
git checkout 9ca00aa37f1ca4c2dcb12978ef61fa8d12186ca7
cd ssdeep-lib/
autoreconf
automake --add-missing
autoreconf
./configure --prefix=`pwd`/../../../../builds/libs/ssdeep-lib CC=clang CXX=clang++
make && make install
