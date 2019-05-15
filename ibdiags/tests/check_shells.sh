#!/bin/dash

rc=0
tools=`file ./scripts/* | grep shell | awk -F: '{ print $1; }'`

for tool in $tools; do
	if ! /bin/dash -n $tool ; then
		echo "ERROR: $tool has non-supported extentions (eg. 'Bashisms')"
		rc=1
	fi
done

exit $rc

