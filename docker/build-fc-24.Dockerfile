# This Dockerfile will create an image suitable for building on Fedora Core 24
# See do_docker.py for how to use this.
FROM fedora:24
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

RUN dnf install -y \
	cmake \
	gcc \
	libnl3-devel \
	pkgconfig \
	python \
	rpm-build \
	valgrind-devel \
    	ninja-build \
	&& dnf clean all

# Why you gotta be different Fedora, why?
RUN ln -sf /usr/bin/ninja-build /usr/local/bin/ninja
