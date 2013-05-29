#!/bin/sh
#
# This generates a version string which includes recent version as
# specified in correspondent sub project's configure.in file, plus
# git revision abbreviation in the case if sub-project HEAD is different
# from recent tag, plus "-dirty" suffix if local uncommitted changes are
# in the sub project tree.
#

usage()
{
	echo "Usage: $0"
	exit 2
}

cd `dirname $0`

packege=`basename \`pwd\``
conf_file=configure.ac
version=`cat $conf_file | sed -ne '/AC_INIT.*.*/s/^AC_INIT.*, \(.*\),.*$/\1/p'`

git diff --quiet $packege-$version..HEAD -- ./ > /dev/null 2>&1
if [ $? -eq 1 ] ; then
	abbr=`git rev-parse --short --verify HEAD 2>/dev/null`
	if [ ! -z "$abbr" ] ; then
		version="${version}_${abbr}"
	fi
fi

git diff-index --quiet HEAD -- ./> /dev/null 2>&1
if [ $? -eq 1 ] ; then
	version="${version}_dirty"
fi

echo $version
