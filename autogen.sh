#! /bin/sh

set -x
aclocal -I config
autoheader
automake --foreign --add-missing --copy
autoconf
