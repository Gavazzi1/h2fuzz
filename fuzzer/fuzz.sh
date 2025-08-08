#!/bin/bash

mkdir -p out
timeout 72h h2_fuzz/h2_fuzz /corpus -artifact_prefix=out/ -detect_leaks=0 -max_len=4096 -jobs=64 -workers=64 -verbosity=1 -dict=/fuzzer/dicts/minimal.dict
