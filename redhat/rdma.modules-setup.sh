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
	inst /etc/rdma/rdma.conf
	inst /etc/rdma/mlx4.conf
	inst /etc/rdma/sriov-vfs
	inst /usr/libexec/rdma-init-kernel
	inst /usr/libexec/rdma-fixup-mtrr.awk
	inst /usr/libexec/mlx4-setup.sh
	inst /usr/libexec/rdma-set-sriov-vf
	inst /usr/lib/modprobe.d/libmlx4.conf
	inst_multiple lspci setpci awk sleep
	inst_multiple -o /etc/modprobe.d/mlx4.conf
	inst_rules 98-rdma.rules 70-persistent-ipoib.rules
}

installkernel() {
	hostonly='' instmods =drivers/infiniband =drivers/net/ethernet/mellanox =drivers/net/ethernet/chelsio =drivers/net/ethernet/cisco =drivers/net/ethernet/emulex =drivers/target
	hostonly='' instmods crc-t10dif crct10dif_common
}
