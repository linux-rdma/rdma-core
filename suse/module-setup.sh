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
	inst /etc/rdma/modules/infiniband.conf
	inst /etc/rdma/modules/iwarp.conf
	inst /etc/rdma/modules/opa.conf
	inst /etc/rdma/modules/rdma.conf
	inst /etc/rdma/modules/roce.conf
	inst /usr/lib/mlx4-setup.sh
	inst_multiple lspci setpci awk sleep
	inst_rules 60-rdma-persistent-naming.rules 70-persistent-ipoib.rules 75-rdma-description.rules 90-rdma-hw-modules.rules 90-rdma-ulp-modules.rules
	inst_multiple -o \
                  $systemdsystemunitdir/rdma-hw.target \
                  $systemdsystemunitdir/rdma-load-modules@.service
}

installkernel() {
	hostonly='' instmods =drivers/infiniband =drivers/net/ethernet/mellanox =drivers/net/ethernet/chelsio =drivers/net/ethernet/cisco =drivers/net/ethernet/emulex =drivers/target
	hostonly='' instmods crc-t10dif crct10dif_common
}
