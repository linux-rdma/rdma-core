# Configure Soft-RoCE (RXE):

Create RXE device over network interface (e.g. eth0):

	# rdma link add rxe_eth0 type rxe netdev eth0

Use the status command to display the current configuration:

	# rdma link

If you are using a Mellanox HCA, make sure that the mlx4_ib/mlx5_ib kernel
module is not loaded (modprobe –rv mlx4_ib) in the soft-RoCE machine.  Now you
have an Infiniband device called “rxe0_eth0” that can be used to run any RoCE
app.
