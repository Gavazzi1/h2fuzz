#!/bin/bash

docker run --name h2_cloudflare -d --rm -e "EXITHOST=cloudflare.h2fuzz.website" cdn_common
