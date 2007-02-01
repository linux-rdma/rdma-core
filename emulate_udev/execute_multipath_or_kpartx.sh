#!/bin/bash
#
# Copyright (c) 2007 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
#  $Id$
#


if [ $# -ne 1 ] ; then
	echo usage: $0 [dir_name]
	exit 1
fi

MULTIPATH_SYMLINK_DEVICES_DIR=/dev/new_disk/
KPARTX_SYMLINK_DEVICES_DIR=/dev/new_dm_disk/

SYMLINK_DEVICES_DIR=$1
if [ $1 = $MULTIPATH_SYMLINK_DEVICES_DIR ] ; then
	EXISTING_DEVICES_LIST=/var/cache/srp_ha_existing_storage_devices
	NEW_DEVICES_LIST=/var/cache/srp_ha_new_storage_devices
	DIFF_FILE=/tmp/srp_ha_devices_diff.$$
	EXECUTE_FILE=/tmp/srp_ha_run.$$
else
	EXISTING_DEVICES_LIST=/var/cache/srp_ha_existing_dm_devices
	NEW_DEVICES_LIST=/var/cache/srp_ha_new_dm_devices
	DIFF_FILE=/tmp/srp_ha_dm_devices_diff.$$
	EXECUTE_FILE=/tmp/srp_ha_run.$$
fi

touch $EXISTING_DEVICES_LIST
ls $SYMLINK_DEVICES_DIR | grep -v dummy > $NEW_DEVICES_LIST
diff $EXISTING_DEVICES_LIST $NEW_DEVICES_LIST > $DIFF_FILE
mv $NEW_DEVICES_LIST $EXISTING_DEVICES_LIST
if [ $1 =  $MULTIPATH_SYMLINK_DEVICES_DIR ] ; then
	grep \> $DIFF_FILE | awk -F\- '{print "multipath " $2":"$3 " &"}' > $EXECUTE_FILE
else
	grep \> $DIFF_FILE | grep -v p | awk '{print "kpartx -a /dev/mapper/" $2 " &"}' > $EXECUTE_FILE
fi
source $EXECUTE_FILE
rm $DIFF_FILE
rm $EXECUTE_FILE

