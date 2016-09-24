# Using ibsrpdm

ibsrpdm is used for discovering and connecting to SRP SCSI targets on
InfiniBand fabrics.  These targets can be accessed with the InfiniBand SRP
initiator module, "ib_srp," included in Linux kernels 2.6.15 and newer.

To run ibsrpdm, the ib_umad module must be loaded, as well as an appropriate
low-level driver for the installed IB hardware.

With no command line parameters, ibsrpdm displays information about
SRP targets in human-readable form:

    # ibsrpdm
    IO Unit Info:
        port LID:        0009
        port GID:        fe800000000000000005ad00000013e9
        change ID:       73b0
        max controllers: 0x01

        controller[  1]
            GUID:      0005ad00000013e7
            vendor ID: 0005ad
            device ID: 0005ad
            IO class : 0100
            ID:        Topspin SRP/FC TCA
            service entries: 2
                service[  0]: 0000000000000066 / SRP.T10:20030003BA27CC7A
                service[  1]: 0000000000000066 / SRP.T10:20030003BA27CF53

With the "-c" flag, ibsrpdm displays information in a form that can be
written to the kernel SRP initiators add_target file to connect to the
SRP targets.  For example:

    # ibsrpdm -c
    id_ext=20030003BA27CC7A,ioc_guid=0005ad00000013e7,dgid=fe800000000000000005ad00000013e9,pkey=ffff,service_id=0000000000000066
    id_ext=20030003BA27CF53,ioc_guid=0005ad00000013e7,dgid=fe800000000000000005ad00000013e9,pkey=ffff,service_id=0000000000000066

Given this, the command below will connect to the first target
discovered from the first port of the local HCA device "mthca0":

    # echo -n id_ext=20030003BA27CC7A,ioc_guid=0005ad00000013e7,dgid=fe800000000000000005ad00000013e9,pkey=ffff,service_id=0000000000000066 > /sys/class/infiniband_srp/srp-mthca0-1/add_target
