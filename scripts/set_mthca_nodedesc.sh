#!/bin/sh

# set the node_desc field in the mthca to the hostname

. /etc/sysconfig/network

echo -n "$HOSTNAME" >> /sys/class/infiniband/mthca0/node_desc

exit 0
