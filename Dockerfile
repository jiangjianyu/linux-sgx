FROM ubuntu:16.04

WORKDIR /

# install dependency for linux-sgx
RUN apt-get update
RUN apt-get install build-essential ocaml automake autoconf libtool wget python -y
RUN apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev -y
RUN apt-get install git -y

COPY ./ /linux-sgx

WORKDIR /linux-sgx

RUN git apply psw_installer.patch

RUN make clean
RUN make sdk_install_pkg
RUN make psw_install_pkg -j

RUN chmod +x ./linux/installer/bin/*.bin

RUN mkdir /opt/intel/

WORKDIR /opt/intel/

RUN /linux-sgx/linux/installer/bin/sgx_linux_x64_psw*.bin
RUN echo "yes" | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk*.bin
