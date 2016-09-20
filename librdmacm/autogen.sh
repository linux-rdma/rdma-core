#! /bin/sh

set -x
test -d ./config || mkdir ./config
autoreconf -ifv -I config
