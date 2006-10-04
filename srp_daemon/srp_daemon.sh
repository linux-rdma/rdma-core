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

# Check if there is another copy of running srp_daemon.sh
if [ -s $pidfile ]; then
    read line < $pidfile
    for p in $line
    do
        if [ -z "${p//[0-9]/}" -a -d "/proc/$p" ]; then
            if [ "$p" != "$mypid" ]; then
                echo "$(basename $0) is already running. Exiting."
                exit 1
            fi
        else
            # pid file exist but no process running
            echo $mypid > $pidfile 
        fi
    done
else
    echo $mypid > $pidfile 
fi

# Check once more to prevent race condition
if [ -s $pidfile ]; then
    read line < $pidfile
    for p in $line
    do
        if [ -z "${p//[0-9]/}" -a -d "/proc/$p" ]; then
            if [ "$p" != "$mypid" ]; then
                echo "$(basename $0) is already running. Race detected. Exiting."
                exit 1
            fi
        fi
    done
else
    echo "Failed to create $pidfile. Exiting."
    exit 1
fi

touch ${log}

trap 'trap_handler' 2 15

while [ ! -d ${ibdir} ]
do
    sleep 30
done


for hca_id in `/bin/ls -1 ${ibdir}`
do
    for port in `/bin/ls -1 ${ibdir}/${hca_id}/ports/`
    do
        ${prog} -e -c -n -i -${hca_id} -p ${port} -R ${retries} &
        pids="$pids $!"
    done
done

wait
