#!/bin/sh
#
# This simple script will collect outputs of ibroute for all switches
# on the subnet and drop it on stdout. It can be used for MFTs dump
# generation.
#

usage ()
{
	echo "usage: $0 [-D]"
	exit 2
}

dump_by_lid ()
{
for sw_lid in `ibswitches \
		| sed -ne 's/^.* lid \([0-9a-f]*\) .*$/\1/p'` ; do
	ibroute -M $sw_lid
done
}

dump_by_dr_path ()
{
for sw_dr in `ibnetdiscover -v \
		| sed -ne '/^DR path .* switch /s/^DR path \[\(.*\)\].*$/\1/p' \
		| sed -e 's/\]\[/,/g' \
		| sort -u` ; do
	ibroute -D ${sw_dr}
done
}


if [ "$1" = "-D" ] ; then
	dump_by_dr_path
elif [ -z "$1" ] ; then
	dump_by_lid
else
	usage
fi

exit
