#!/bin/bash

docker run --name h2_cloudfront -d --rm -e "EXITHOST=d2plqgx06492db.cloudfront.net" cdn_common
