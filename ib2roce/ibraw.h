/*
 * Create a flow on IB using MSFLINT
 */

int set_ib_sniffer(const char *dev, unsigned port, struct ibv_qp *qp);
int clear_ib_sniffer(unsigned port, struct ibv_qp *qp);


