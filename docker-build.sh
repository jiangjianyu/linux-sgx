#!/bin/bash

# dep
sudo docker build ./ -t uranus-linux-sdk:latest

# build
sudo docker run -i -v ${PWD}:/linux-sgx/:Z uranus-linux-sdk:latest bash -c "cd /linux-sgx/;./download_prebuilt.sh; make clean;make sdk_install_pkg;make psw_install_pkg"
