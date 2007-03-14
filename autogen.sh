#! /bin/sh

mkdir -p config
aclocal -I config
autoheader
automake --foreign --add-missing --copy
autoconf
