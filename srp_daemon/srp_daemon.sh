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


prog=/usr/sbin/srp_daemon
params=$@
ibdir="/sys/class/infiniband"
log="/var/log/srp_daemon.log"
retries=60
pids=""
pidfile=/var/run/srp_daemon.sh.pid
mypid=$$

trap_handler()
{
    if [ -n "$pids" ]; then
        kill -15 $pids > /dev/null 2>&1
    fi
    logger -i -t "$(basename $0)" "killing $prog."
    /bin/rm -f $pidfile
    exit 0
}

rotate_log()
{
        local log=$1
        if [ -s ${log} ]; then
                cat ${log} >> ${log}.$(date +%Y-%m-%d)
                /bin/rm -f ${log}
        fi
        touch ${log}
}

# Check if there is another copy running of srp_daemon.sh
if [ -f $pidfile -a ! -e /proc/$(cat $pidfile 2>/dev/null)/status ]; then
    rm -f $pidfile
fi
if ! echo $mypid > $pidfile.$mypid; then
    echo "Creating $pidfile.$mypid failed"
    exit 1
fi
mv -n $pidfile.$mypid $pidfile
if [ -e $pidfile.$mypid ]; then
    rm -f $pidfile.$mypid
    echo "$(basename $0) is already running. Exiting."
    exit 1
fi

rotate_log ${log}

trap 'trap_handler' 2 15

while [ ! -d ${ibdir} ]
do
    sleep 30
done


for hca_id in `/bin/ls -1 ${ibdir}`
do
    for port in `/bin/ls -1 ${ibdir}/${hca_id}/ports/`
    do
        ${prog} -e -c -n -i ${hca_id} -p ${port} -R ${retries} ${params} >>${log} 2>&1 &
        pids="$pids $!"
    done
done

wait
