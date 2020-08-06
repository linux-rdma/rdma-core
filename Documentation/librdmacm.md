# Device files

The userspace CMA uses a single device file regardless of the number
of adapters or ports present.

To create the appropriate character device file automatically with
udev, a rule like

    KERNEL="rdma_cm", NAME="infiniband/%k", MODE="0666"

can be used.  This will create the device node named

    /dev/infiniband/rdma_cm

or you can create it manually

  mknod /dev/infiniband/rdma_cm c 231 255


# Common issues

Using multiple interfaces
:	The librdmacm does support multiple interfaces.  To make use
	of multiple interfaces, however, you need to instruct linux
	to only send ARP replies on the interface targeted in the ARP
	request.  This can be done using a command similar to the
	following:

		sysctl -w net.ipv4.conf.all.arp_ignore=2

	Without this change, it's possible for linux to resopnd to ARP
	requests on a different interface (IP address) than the IP
	address carried in the ARP request.  This causes the RDMA stack
	to incorrectly map the remote IP address to the wrong RDMA
	device.

Using loopback
:	The librdmacm relies on ARP to resolve IP address to RDMA
	addresses.  To support loopback connections between different
	ports on the same system, ARP must be enabled for local
	resolution:

		sysctl net.ipv4.conf.all.accept_local=1

	Without this setting, loopback connections may timeout
	during address resolution.
