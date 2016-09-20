#!/bin/bash
fedora_dist=$1

NAME=libhfi1

make distclean
rm -rf *.tar.gz
rm -rf BUILD RPMS SOURCES SPECS SRPMS BUILDROOT

./autogen.sh
./configure
if [[ -z $fedora_dist ]]; then
	make dist am__tar='tar chf - $$tardir'
else
	make fedora_dist am__tar='tar chf - $$tardir'
fi

mkdir -p ./{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
cp ./$NAME-*.tar.gz SOURCES
cp $NAME.spec SPECS
rpmbuild -bs --define "_topdir $PWD" --nodeps SPECS/$NAME.spec
