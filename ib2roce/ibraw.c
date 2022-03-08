/*
 * Create a flow on IB using MSFLINT
 */

#define MST_UL

#include <stdio.h>
#include <stdlib.h>
#include <infiniband/verbs.h>

#include <tools_layouts/icmd_layouts.h>
#include <cmdif/icmd_cif_common.h>
#include <cmdif/icmd_cif_open.h>
#include <common/compatibility.h>

#include "ibraw.h"

static mfile *mf = NULL;

static int ib_sniffer(unsigned port, struct ibv_qp *qp, int mode)
{
	struct connectib_icmd_set_port_sniffer set_port_sniffer;
 	int rc;

  	 // To disable write protection
	mwrite4(mf, 0x23f0, 0xbadc0ffe);

	memset(&set_port_sniffer, 0, sizeof(struct connectib_icmd_set_port_sniffer));
	set_port_sniffer.port        = port;
	set_port_sniffer.sniffer_qpn = qp->qp_num;
 	set_port_sniffer.sx_rx_ = 0;
 	set_port_sniffer.attach_detach_ = mode;

 	rc = gcif_set_port_sniffer(mf, &set_port_sniffer);
  	if (rc != GCIF_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to set port sniffer1: %s\n", gcif_err_str(rc));
        	goto err;
    	}

	set_port_sniffer.sx_rx_ = 1;
	rc = gcif_set_port_sniffer(mf, &set_port_sniffer);
	if (rc != GCIF_STATUS_SUCCESS) {
        	fprintf(stderr, "Failed to set port sniffer2: %s\n", gcif_err_str(rc));
     		goto err;
	}

	return 0;

err:
	mclose(mf);
	mf = NULL;

	return 1;
}

int set_ib_sniffer(const char *dev, unsigned port, struct ibv_qp *qp)
{
	mf = mopen(dev);

	if (!mf) {
		fprintf(stderr, "Failed to open %s for sniffing\n", dev);
		return 1;
	}
	return ib_sniffer(port, qp, 1);
}

int clear_ib_sniffer(unsigned port, struct ibv_qp *qp)
{
	int rc;
       
	if (!mf)
		return -EINVAL;

	rc = ib_sniffer(port, qp, 0);

	mclose(mf);

	return rc;
}

