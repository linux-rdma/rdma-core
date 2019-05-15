#! /bin/sh

# create config dir if not exist
test -d config || mkdir config

set -x
doc/generate
autoreconf -ifv -I config
