#!/bin/bash

rm -rf streams
rm -rf base_streams
mkdir streams
mkdir base_streams

python3 main.py -c config_nomut
python3 extract_base.py
rm streams/*
python3 main.py -c config
cp base_streams/* streams/
rm -r base_streams
rm batch0.out
