#!/bin/bash
#
# Copyright (c) 2006 Mellanox Technologies. All rights reserved.
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


prog=run_srp_daemon
ibdir="/sys/class/infiniband"
log="/var/log/srp_daemon.log"
retries=300
pids=""

trap_handler()
{
    if [ -n "$pids" ]; then
        kill -15 $pids > /dev/null 2>&1
    fi
    logger -i -t "$(basename $0)" "killing $prog."
    exit 0
}

touch ${log}

trap 'trap_handler' 2 15

while [ ! -d ${ibdir} ]
do
    usleep 500000
done


for hca_id in `/bin/ls -1 ${ibdir}`
do
    for port in `/bin/ls -1 ${ibdir}/${hca_id}/ports/`
    do
        ${prog} -e -c -i ${hca_id} -p ${port} -R ${retries} &
        pids="$pids $!"
    done
done

wait
