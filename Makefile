OPENIB_ROOT=..
include $(OPENIB_ROOT)/make.inc

SRCS=$(wildcard src/*.c)
LIB_OBJS=$(SRCS:.c=.lo)
LIB_HDRS=$(wildcard include/infiniband/*.h) ../libibcommon/include/infiniband/common.h

PUBLIC_HEADERS=include/infiniband/umad.h

#LIB_STATIC_TARGET=libibumad.a
LIB_SO_TARGET=libibumad.la

EXTRA_CLEAN=

all: $(LIB_SO_TARGET)

install: lib_install public_headers_install

include $(OPENIB_ROOT)/make.rules
