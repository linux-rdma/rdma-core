# This Dockerfile will create an image suitable for building on Centos 7
# See do_docker.py for how to use this.
FROM centos:6
MAINTAINER Jason Gunthorpe <jgunthorpe@obsidianresearch.com>

RUN yum install -y \
	cmake \
	gcc \
	libnl3-devel \
	make \
	pkgconfig \
	python \
	rpm-build \
	valgrind-devel \
	&& yum clean all
