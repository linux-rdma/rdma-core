#! /bin/sh

# create config dir if not exist
test -d config || mkdir config

rst2manexe=`which rst2man`
if [ "$rst2manexe" == "" ]; then
	echo "ERROR: Building from source requires rst2man to build the man pages"
fi

set -x
aclocal -I config
libtoolize --force --copy
autoheader
doc/generate
automake --foreign --add-missing --copy
autoconf
