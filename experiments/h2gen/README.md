# H2Gen

This directory contains a modified version of `FrameShifter` that writes all mutated HTTP/2 requests to the filesytem, rather than sending them to a reverse proxy.

All functionality that processes the returned HTTP/1 response is also removed.

It is designed to be used to create an initial corpus for h2fuzz experiments.

Create a python virtualenv using the requirements.txt, then within the virtualenv, run `./makecorpus.sh`
