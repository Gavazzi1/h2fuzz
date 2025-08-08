#!/bin/bash

docker run --name h2_azure -d --rm -e "EXITHOST=h2fuzz.azureedge.net" cdn_common
