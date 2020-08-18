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
	inst /usr/libexec/mlx4-setup.sh
	inst /usr/lib/modprobe.d/libmlx4.conf
	inst_multiple lspci setpci awk sleep
	inst_multiple -o /etc/modprobe.d/mlx4.conf
	inst_rules 70-persistent-ipoib.rules
}

installkernel() {
	hostonly='' instmods =drivers/infiniband =drivers/net/ethernet/mellanox =drivers/net/ethernet/chelsio =drivers/net/ethernet/cisco =drivers/net/ethernet/emulex =drivers/target
	hostonly='' instmods crc-t10dif crct10dif_common
}
