FROM ubuntu:16.04

WORKDIR /

# install dependency for linux-sgx
RUN apt-get update
RUN apt-get install build-essential ocaml automake autoconf libtool wget python -y
RUN apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev -y
RUN apt-get install git -y
