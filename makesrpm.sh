#!/bin/bash
NAME=libhfiverbs

make distclean
rm -rf *.tar.gz
rm -rf BUILD RPMS SOURCES SPECS SRPMS BUILDROOT

./autogen.sh
./configure
make dist am__tar='tar chf - $$tardir'
 
mkdir -p ./{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
cp ./$NAME-*.tar.gz SOURCES
cp $NAME.spec SPECS
rpmbuild -bs --define "_topdir $PWD" --nodeps SPECS/$NAME.spec
