# Device files

The userspace CM uses a device file per adapter present.

To create the appropriate character device file automatically with
udev, a rule like

    KERNEL="ucm*", NAME="infiniband/%k", MODE="0666"

can be used.  This will create the device node named

    /dev/infiniband/ucm0

for the first HCA in the system, or you can create it manually

  mknod /dev/infiniband/ucm0 c 231 224
