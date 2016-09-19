# Configure Soft-RoCE (RXE):

Load rdma_rxe kernel module using the rxe_cfg script included in the librxe RPM:

	# rxe_cfg start (this might require sudo or root privileges)

Create RXE device over network interface (e.g. eth0):

	# rxe_cfg add eth0

Use the status command to display the current configuration:
rxe_cfg status

If configured successfully, you should see output similar to the following:

```
    Name  Link  Driver   Speed  NMTU  IPv4_addr  RDEV  RMTU
    eth0  yes   mlx4_en                          rxe0  1024  (3)
```

If you are using a Mellanox HCA: Need to make sure that the mlx4_ib kernel module is not loaded (modprobe –rv mlx4_ib) in the soft-RoCE machine.
Now you have an Infiniband device called “rxe0” that can be used to run any RoCE app.
