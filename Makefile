OPENIB_ROOT=../
include $(OPENIB_ROOT)/make.inc

SRCS=$(wildcard src/*.c)
LIB_OBJS=$(SRCS:.c=.lo)
LIB_HDRS=$(wildcard *.h)

PUBLIC_HEADERS=

#LIB_STATIC_TARGET=libibmad.a
LIB_SO_TARGET=libibmad.la

EXTRA_CLEAN=

all: .depend $(LIB_SO_TARGET) #$(LIB_STATIC_TARGET)

install: lib_install # public_headers_install

include $(OPENIB_ROOT)/make.rules
