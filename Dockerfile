FROM ubuntu:16.04

RUN apt-get update \
    && apt-get install automake git build-essential libtool m4 automake cmake -y \
    && apt-get clean cache

RUN cp ./ /tee-sdk/

WORKDIR /tee-sdk

RUN make -j

