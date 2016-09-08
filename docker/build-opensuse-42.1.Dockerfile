# This Dockerfile will create an image suitable for building on OpenSuSE Leap 42.1
# See do_docker.py for how to use this.
FROM opensuse:42.1
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

RUN zypper refresh

RUN zypper --non-interactive install \
	cmake \
	gcc \
	libnl3-devel \
	make \
	ninja \
	pkg-config \
	python \
	rpm-build \
	valgrind-devel
