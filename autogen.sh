#! /bin/sh

set -x
if [ ! -d config ]
then
   mkdir config
fi
aclocal -I config
libtoolize --force --copy
autoheader
automake --foreign --add-missing --copy
autoconf
