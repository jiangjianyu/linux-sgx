#!/bin/bash

# dep
sudo docker build ./ -t linux-sgx-uranus:latest

# build
sudo docker run -i -v ${PWD}:/build/:Z linux-sgx-uranus:latest bash -c "cp /linux-sgx/linux/installer/bin/*.bin /build/"
