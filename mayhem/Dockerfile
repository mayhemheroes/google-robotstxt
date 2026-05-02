# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 AS builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake git

## Add source code to the build stage.
ADD . /robotstxt
WORKDIR /robotstxt

## Build
RUN mkdir build && cd build && \
    cmake .. -DROBOTS_FUZZ=On -DCMAKE_CXX_STANDARD=17 -DCMAKE_CXX_FLAGS="-std=c++17" && \
    make -j$(nproc)

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /robotstxt/build/mayhem/fuzz_robots /fuzz_robots
COPY --from=builder /robotstxt/build/librobots.so /usr/lib/librobots.so
#RUN apt-get update && \
#    DEBIAN_FRONTEND=noninteractive apt-get install -y libboost-thread1.74.0 libboost-atomic1.74.0 libboost-filesystem1.74.0 libboost-system1.74.0 libboost-program-options1.74.0 libboost-date-time1.74.0 libboost-chrono1.74.0 libc6-i386 libc6 libgcc-s1 lib32gcc-s1 libc6 libc6-i386

## Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_robots
