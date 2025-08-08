#!/bin/bash

docker run --name h2_akamai -d --rm -e "EXITHOST=akamai.h2fuzz.website" cdn_common
