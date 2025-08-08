#!/bin/bash

docker run --name h2_fastly -d --rm -e "EXITHOST=h2fuzz.freetls.fastly.net" cdn_common
