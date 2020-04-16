FROM ubuntu:16.04

WORKDIR /

# install dependency for linux-sgx
RUN apt-get update && \
    apt-get install build-essential ocaml automake autoconf libtool wget python \
		    libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev \
		    git -y && \
    apt-get clean

COPY ./ /linux-sgx

WORKDIR /linux-sgx

RUN git apply psw_installer.patch

RUN make clean; make sdk_install_pkg; make psw_install_pkg -j

RUN chmod +x ./linux/installer/bin/*.bin

RUN mkdir /opt/intel/

WORKDIR /opt/intel/

RUN /linux-sgx/linux/installer/bin/sgx_linux_x64_psw*.bin
RUN echo "yes" | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk*.bin

RUN mkdir -p /build/

RUN mv /linux-sgx/linux/installer/bin/* /build/
RUN rm -rf /linux-sgx
