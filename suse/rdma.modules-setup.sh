#!/bin/bash

check() {
	[ -n "$hostonly" -a -c /sys/class/infiniband_verbs/uverbs0 ] && return 0
	[ -n "$hostonly" ] && return 255
	return 0
}

depends() {
	return 0
}

install() {
	inst /etc/rdma/mlx4.conf
	inst /etc/rdma/sriov-vfs
	inst /usr/lib/mlx4-setup.sh
	inst /usr/lib/rdma-set-sriov-vf
	inst /usr/lib/modprobe.d/50-libmlx4.conf
	inst_multiple lspci setpci sleep
	inst_multiple -o /etc/modprobe.d/mlx4.conf
	inst_rules 98-rdma-sriov.rules 70-persistent-ipoib.rules
}

installkernel() {
	hostonly='' instmods =drivers/infiniband =drivers/net/ethernet/mellanox =drivers/net/ethernet/chelsio =drivers/net/ethernet/cisco =drivers/net/ethernet/emulex =drivers/target
	hostonly='' instmods crc-t10dif crct10dif_common
}
