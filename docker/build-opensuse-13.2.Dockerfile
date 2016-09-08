# This Dockerfile will create an image suitable for building on OpenSuSE 13.2
# See do_docker.py for how to use this.
FROM opensuse:13.2
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

RUN zypper refresh

RUN zypper --non-interactive install \
	cmake \
	gcc \
	libnl3-devel \
	make \
	pkg-config \
	python \
	rpm-build \
	valgrind-devel

RUN zypper --non-interactive install \
    ninja
