# librxe-dev
Development repository for RXE user space code.
Soft RDMA over Ethernet (RoCE) Driver

Source

Kernel Space Driver

This repository contains a full kernel source tree, with the RoCE driver code located in the directory drivers/infiniband/hw/rxe.

Github: https://github.com/SoftRoCE/rxe-dev.git 
Active Branch: master-next
User Space Library

Github: https://github.com/SoftRoCE/librxe-dev.git (this repository)
Current Version: librxe-1.0.0
Build Instructions

Compile and install kernel:

Clone kernel git:
git clone https://github.com/SoftRoCE/rxe-dev.git
Compile kernel:
Enter the source directory cd rxe-dev
cp /boot/config-$(uname –r) .config
make menuconfig
Need to enable “Software RDMA over Ethernet (RoCE) driver” in category "Device Drivers -> Infiniband"
Need to enable CONFIG_INFINIBAND_ADDR_TRANS=y and CONFIG_INFINIBAND_ADDR_TRANS_CONFIGFS=y in new config file .config
make –j 32
make modules_install
make install
Verify that the new kernel entry is added (e.g. to grub); if not, need to add it manually.
Boot with new kernel.
Install user space library (librxe):

Install the following package (example shown using RedHat):
yum install perl-Switch (name might vary according to distribution)
Make sure that the following upstream user space libraries are installed:
libibverbs
libibverbs-devel
libibverbs-utils
librdmacm
librdmacm-devel
librdmacm-utils
Compile and install user space library librxe:
git clone https://github.com/SoftRoCE/librxe-dev.git
cd librxe-dev
./configure --libdir=/usr/lib64/ --prefix=
make
make install
Configure Soft-RoCE (RXE):

Load ib_rxe kernel module using the rxe_cfg script included in the librxe RPM:
rxe_cfg start (this might require sudo or root privileges)
Create RXE device over network interface (e.g. eth0):
rxe_cfg add eth0
Use the status command to display the current configuration:
rxe_cfg status
If configured successfully, you should see output similar to the following:
    Name  Link  Driver   Speed  NMTU  IPv4_addr  RDEV  RMTU         
    eth0  yes   mlx4_en                          rxe0  1024  (3) 
If you are using a Mellanox HCA: Need to make sure that the mlx4_ib kernel module is not loaded (modprobe –rv mlx4_ib) in the soft-RoCE machine.
Now you have an Infiniband device called “rxe0” that can be used to run any RoCE app.
