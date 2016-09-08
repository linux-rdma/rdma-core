# This Dockerfile aims to duplicate the configuration we use in travis
# See do_docker.py for how to use this.
FROM ubuntu:14.04
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

RUN /bin/echo -e "deb http://archive.ubuntu.com/ubuntu/ trusty-updates main universe\ndeb http://archive.ubuntu.com/ubuntu trusty main universe\ndeb http://security.ubuntu.com/ubuntu trusty-security main universe" > /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
     software-properties-common

RUN apt-add-repository -y "ppa:ubuntu-toolchain-r/test"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    debhelper \
    dh-systemd \
    gcc \
    gcc-6 \
    gcc-multilib \
    lib32gcc-6-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    make \
    ninja-build \
    pkg-config \
    python \
    valgrind \
    && \
    rm -f /var/cache/apt/archives/*.deb

ENV CC="gcc-6"
ENV CFLAGS="-Werror"
