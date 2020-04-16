#!/bin/bash

# dep
sudo docker build ./ -t jyjiang/linux-sgx:latest

# build
sudo docker run -i -v ${PWD}:/build-external/:Z jyjiang/linux-sgx:latest bash -c "cp /build/*.bin /build-external/"
