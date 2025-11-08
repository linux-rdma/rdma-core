#!/bin/bash

check() {
    [ -n "$hostonly" ] && [ -e /sys/class/infiniband_verbs/uverbs0 ] && return 0
    [ -n "$hostonly" ] && return 255
    return 255
}

depends() {
    echo systemd
    return 0
}

install() {
    inst /etc/rdma/mlx4.conf
    inst /etc/rdma/modules/infiniband.conf
    inst /etc/rdma/modules/iwarp.conf
    inst /etc/rdma/modules/opa.conf
    inst /etc/rdma/modules/rdma.conf
    inst /etc/rdma/modules/roce.conf
    inst /usr/libexec/mlx4-setup.sh
    inst_multiple lspci setpci awk sleep
    inst_rules 60-rdma-persistent-naming.rules 70-persistent-ipoib.rules 75-rdma-description.rules 90-rdma-hw-modules.rules 90-rdma-ulp-modules.rules 90-rdma-umad.rules
    inst_multiple -o \
        inst /usr/lib/modprobe.d/libmlx4.conf \
        "$systemdsystemunitdir"/rdma-hw.target \
        "$systemdsystemunitdir"/rdma-load-modules@.service

    for i in \
        rdma-load-modules@rdma.service \
        rdma-load-modules@roce.service \
        rdma-load-modules@infiniband.service; do
        $SYSTEMCTL -q --root "$initdir" add-wants initrd.target "$i"
    done
}

installkernel() {
    hostonly='' instmods "=drivers/infiniband" "=drivers/net/ethernet/mellanox" "=drivers/net/ethernet/chelsio" "=drivers/net/ethernet/cisco" "=drivers/net/ethernet/emulex" "=drivers/target"
    hostonly='' instmods crc-t10dif crct10dif_common xprtrdma svcrdma
}
