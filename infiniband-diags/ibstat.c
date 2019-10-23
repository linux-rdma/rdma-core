/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2011 Mellanox Technologies LTD.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#define _GNU_SOURCE

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/types.h> /* __be64 */

#include <infiniband/umad.h>

#include <ibdiag_common.h>

static const char * const node_type_str[] = {
	"???",
	"CA",
	"Switch",
	"Router",
	"iWARP RNIC"
};

static void ca_dump(umad_ca_t * ca)
{
	if (!ca->node_type)
		return;
	printf("%s '%s'\n",
	       ((unsigned)ca->node_type <=
		IB_NODE_MAX ? node_type_str[ca->node_type] : "???"),
	       ca->ca_name);
	printf("\t%s type: %s\n",
	       ((unsigned)ca->node_type <=
		IB_NODE_MAX ? node_type_str[ca->node_type] : "???"),
	       ca->ca_type);
	printf("\tNumber of ports: %d\n", ca->numports);
	printf("\tFirmware version: %s\n", ca->fw_ver);
	printf("\tHardware version: %s\n", ca->hw_ver);
	printf("\tNode GUID: 0x%016" PRIx64 "\n", be64toh(ca->node_guid));
	printf("\tSystem image GUID: 0x%016" PRIx64 "\n",
	       be64toh(ca->system_guid));
}

static const char * const port_state_str[] = {
	"???",
	"Down",
	"Initializing",
	"Armed",
	"Active"
};

static const char * const port_phy_state_str[] = {
	"No state change",
	"Sleep",
	"Polling",
	"Disabled",
	"PortConfigurationTraining",
	"LinkUp",
	"LinkErrorRecovery",
	"PhyTest"
};

static int ret_code(void)
{
	int e = errno;

	if (e > 0)
		return -e;
	return e;
}

static int sys_read_string(const char *dir_name, const char *file_name,
			   char *str, int max_len)
{
	char path[256], *s;
	int fd, r;

	r = snprintf(path, sizeof(path), "%s/%s", dir_name, file_name);
	if (r > sizeof(path))
		return -ENOENT;

	if ((fd = open(path, O_RDONLY)) < 0)
		return ret_code();

	if ((r = read(fd, str, max_len)) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return ret_code();
	}

	str[(r < max_len) ? r : max_len - 1] = 0;

	if ((s = strrchr(str, '\n')))
		*s = 0;

	close(fd);
	return 0;
}

static int is_fdr10(umad_port_t *port)
{
	char port_dir[256];
	char rate[32];
	int len, fdr10 = 0;
	char *p;

	len = snprintf(port_dir, sizeof(port_dir), "%s/%s/%s/%d",
		       SYS_INFINIBAND, port->ca_name, SYS_CA_PORTS_DIR,
		       port->portnum);
	if (len < 0 || len > sizeof(port_dir))
		goto done;

	if (sys_read_string(port_dir, SYS_PORT_RATE, rate, sizeof(rate)) == 0) {
		if ((p = strchr(rate, ')'))) {
			if (!strncasecmp(p - 5, "fdr10", 5))
				fdr10 = 1;
		}
	}

done:
	return fdr10;
}

static int port_dump(umad_port_t * port, int alone)
{
	const char *pre = "";
	const char *hdrpre = "";

	if (!port)
		return -1;

	if (!alone) {
		pre = "		";
		hdrpre = "	";
	}

	printf("%sPort %d:\n", hdrpre, port->portnum);
	printf("%sState: %s\n", pre,
	       (unsigned)port->state <=
	       4 ? port_state_str[port->state] : "???");
	printf("%sPhysical state: %s\n", pre,
	       (unsigned)port->phys_state <=
	       7 ? port_phy_state_str[port->phys_state] : "???");
	if (is_fdr10(port))
		printf("%sRate: %d (FDR10)\n", pre, port->rate);
	else if (port->rate != 2)	/* 1x SDR */
		printf("%sRate: %d\n", pre, port->rate);
	else
		printf("%sRate: 2.5\n", pre);
	printf("%sBase lid: %d\n", pre, port->base_lid);
	printf("%sLMC: %d\n", pre, port->lmc);
	printf("%sSM lid: %d\n", pre, port->sm_lid);
	printf("%sCapability mask: 0x%08x\n", pre, ntohl(port->capmask));
	printf("%sPort GUID: 0x%016" PRIx64 "\n", pre, be64toh(port->port_guid));
	printf("%sLink layer: %s\n", pre, port->link_layer);
	return 0;
}

static int ca_stat(const char *ca_name, int portnum, int no_ports)
{
	umad_ca_t ca;
	int r;

	if ((r = umad_get_ca(ca_name, &ca)) < 0)
		return r;

	if (!ca.node_type)
		return 0;

	if (!no_ports && portnum >= 0) {
		if (portnum > ca.numports || !ca.ports[portnum]) {
			IBWARN("%s: '%s' has no port number %d - max (%d)",
			       ((unsigned)ca.node_type <=
				IB_NODE_MAX ? node_type_str[ca.node_type] :
				"???"), ca_name, portnum, ca.numports);
			return -1;
		}
		printf("%s: '%s'\n",
		       ((unsigned)ca.node_type <=
			IB_NODE_MAX ? node_type_str[ca.node_type] : "???"),
		       ca.ca_name);
		port_dump(ca.ports[portnum], 1);
		return 0;
	}

	/* print ca header */
	ca_dump(&ca);

	if (no_ports)
		return 0;

	for (portnum = 0; portnum <= ca.numports; portnum++)
		port_dump(ca.ports[portnum], 0);

	return 0;
}

static int ports_list(struct umad_device_node *first_node,
		      struct umad_device_node *last_node)
{
	__be64 guids[64];
	struct umad_device_node *node;
	int ports, j;

	for (node = first_node; node && node != last_node; node = node->next) {
		if ((ports =
		     umad_get_ca_portguids(node->ca_name, &guids[0], 64)) < 0)
			return -1;

		for (j = 0; j < ports; j++)
			if (guids[j])
				printf("0x%016" PRIx64 "\n", be64toh(guids[j]));
	}
	return 0;
}

static int list_only, short_format, list_ports;

static int process_opt(void *context, int ch)
{
	switch (ch) {
	case 'l':
		list_only++;
		break;
	case 's':
		short_format++;
		break;
	case 'p':
		list_ports++;
		break;
	default:
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct umad_device_node *device_list;
	struct umad_device_node *node;
	struct umad_device_node *first_node;
	struct umad_device_node *last_node;
	int dev_port = -1;
	const char *ca_name;

	const struct ibdiag_opt opts[] = {
		{"list_of_cas", 'l', 0, NULL, "list all IB devices"},
		{"short", 's', 0, NULL, "short output"},
		{"port_list", 'p', 0, NULL, "show port list"},
		{}
	};
	char usage_args[] = "<ca_name> [portnum]";
	const char *usage_examples[] = {
		"-l       # list all IB devices",
		"mthca0 2 # stat port 2 of 'mthca0'",
		NULL
	};

	ibdiag_process_opts(argc, argv, NULL, "CDeGKLPsty", opts, process_opt,
			    usage_args, usage_examples);

	argc -= optind;
	argv += optind;

	if (argc > 1)
		dev_port = strtol(argv[1], NULL, 0);

	if (umad_init() < 0)
		IBPANIC("can't init UMAD library");

	device_list = umad_get_ca_device_list();
	if (!device_list && errno)
		IBPANIC("can't list IB device names");

	if (argc) {
		for (node = device_list; node; node = node->next)
			if (!strncmp(node->ca_name, argv[0],
				     strlen(node->ca_name)))
				break;
		if (!node)
			IBPANIC("'%s' IB device can't be found", argv[0]);

		first_node = node;
		last_node = node->next;
	} else {
		first_node = device_list;
		last_node = NULL;
	}

	if (list_ports) {
		if (ports_list(first_node, last_node) < 0)
			IBPANIC("can't list ports");
		umad_free_ca_device_list(device_list);
		return 0;
	}

	for (node = first_node; node != last_node; node = node->next) {
		ca_name = node->ca_name;
		if (list_only)
			printf("%s\n", ca_name);
		else if (ca_stat(ca_name, dev_port, short_format) < 0)
			IBPANIC("stat of IB device '%s' failed", ca_name);
	}
	umad_free_ca_device_list(device_list);
	return 0;
}
