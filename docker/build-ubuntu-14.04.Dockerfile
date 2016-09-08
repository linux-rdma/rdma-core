# This Dockerfile will create an image suitable for building on Ubuntu Trusty
# See do_docker.py for how to use this.
FROM ubuntu:14.04
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

RUN /bin/echo -e "deb http://archive.ubuntu.com/ubuntu/ trusty-updates main universe\ndeb http://archive.ubuntu.com/ubuntu trusty main universe\ndeb http://security.ubuntu.com/ubuntu trusty-security main universe" > /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    debhelper \
    dh-systemd \
    gcc \
    libnl-3-dev \
    libnl-route-3-dev \
    make \
    ninja-build \
    pkg-config \
    python \
    valgrind \
    && \
    rm -f /var/cache/apt/archives/*.deb
