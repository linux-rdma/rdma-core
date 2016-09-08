# This Dockerfile will create an image suitable for building on Debian Jessie
# See do_docker.py for how to use this.
FROM debian:8
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

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
