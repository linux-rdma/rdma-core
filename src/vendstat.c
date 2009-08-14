/*
 * Copyright (c) 2004-2008 Voltaire Inc.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include "ibdiag_common.h"

#define IS3_DEVICE_ID			47396

#define IB_MLX_VENDOR_CLASS		10
/* Vendor specific Attribute IDs */
#define IB_MLX_IS3_GENERAL_INFO		0x17
#define IB_MLX_IS3_CONFIG_SPACE_ACCESS	0x50
#define IB_MLX_IS4_COUNTER_GROUP_INFO   0x90
#define IB_MLX_IS4_CONFIG_COUNTER_GROUP 0x91
/* Config space addresses */
#define IB_MLX_IS3_PORT_XMIT_WAIT	0x10013C

struct ibmad_port *srcport;

typedef struct {
	uint16_t hw_revision;
	uint16_t device_id;
	uint8_t reserved[24];
	uint32_t uptime;
} is3_hw_info_t;

typedef struct {
	uint8_t resv1;
	uint8_t major;
	uint8_t minor;
	uint8_t sub_minor;
	uint32_t build_id;
	uint8_t month;
	uint8_t day;
	uint16_t year;
	uint16_t resv2;
	uint16_t hour;
	uint8_t psid[16];
	uint32_t ini_file_version;
} is3_fw_info_t;

typedef struct {
	uint8_t resv1;
	uint8_t major;
	uint8_t minor;
	uint8_t sub_minor;
	uint8_t resv2[28];
} is3_sw_info_t;

typedef struct {
	uint8_t reserved[8];
	is3_hw_info_t hw_info;
	is3_fw_info_t fw_info;
	is3_sw_info_t sw_info;
} is3_general_info_t;

typedef struct {
	uint32_t address;
	uint32_t data;
	uint32_t mask;
} is3_record_t;

typedef struct {
	uint8_t reserved[8];
	is3_record_t record[18];
} is3_config_space_t;

#define COUNTER_GROUPS_NUM 2

typedef struct {
	uint8_t reserved1[8];
	uint8_t reserved[3];
	uint8_t num_of_counter_groups;
	uint32_t group_masks[COUNTER_GROUPS_NUM];
} is4_counter_group_info_t;

typedef struct {
	uint8_t reserved[3];
	uint8_t group_select;
} is4_group_select_t;

typedef struct {
	uint8_t reserved1[8];
	uint8_t reserved[4];
	is4_group_select_t group_selects[COUNTER_GROUPS_NUM];
} is4_config_counter_groups_t;

void counter_groups_info(ib_portid_t * portid, int port)
{
	char buf[1024];
	ib_vendor_call_t call;
	is4_counter_group_info_t *cg_info;
	int i, num_cg;

	memset(&call, 0, sizeof(call));
	call.mgmt_class = IB_MLX_VENDOR_CLASS;
	call.method = IB_MAD_METHOD_GET;
	call.timeout = ibd_timeout;
	call.attrid = IB_MLX_IS4_COUNTER_GROUP_INFO;
	call.mod = port;

	/* Counter Group Info */
	memset(&buf, 0, sizeof(buf));
	if (!ib_vendor_call_via(&buf, portid, &call, srcport))
		IBERROR("counter group info query");

	cg_info = (is4_counter_group_info_t *) & buf;
	num_cg = cg_info->num_of_counter_groups;
	printf("counter_group_info:\n");
	printf("%d counter groups\n", num_cg);
	for (i = 0; i < num_cg; i++)
		printf("group%d mask %#x\n", i, ntohl(cg_info->group_masks[i]));
}

/* Group0 counter config values */
#define IS4_G0_PortXmtDataSL_0_7  0
#define IS4_G0_PortXmtDataSL_8_15 1
#define IS4_G0_PortRcvDataSL_0_7  2

/* Group1 counter config values */
#define IS4_G1_PortXmtDataSL_8_15 1
#define IS4_G1_PortRcvDataSL_0_7  2
#define IS4_G1_PortRcvDataSL_8_15 8

static int cg0, cg1;

void config_counter_groups(ib_portid_t * portid, int port)
{
	char buf[1024];
	ib_vendor_call_t call;
	is4_config_counter_groups_t *cg_config;

	memset(&call, 0, sizeof(call));
	call.mgmt_class = IB_MLX_VENDOR_CLASS;
	call.attrid = IB_MLX_IS4_CONFIG_COUNTER_GROUP;
	call.timeout = ibd_timeout;
	call.mod = port;
	/* configure counter groups for groups 0 and 1 */
	call.method = IB_MAD_METHOD_SET;

	memset(&buf, 0, sizeof(buf));
	cg_config = (is4_config_counter_groups_t *) & buf;

	printf("counter_groups_config: configuring group0 %d group1 %d\n", cg0,
	       cg1);
	cg_config->group_selects[0].group_select = (uint8_t) cg0;
	cg_config->group_selects[1].group_select = (uint8_t) cg1;

	if (!ib_vendor_call_via(&buf, portid, &call, srcport))
		IBERROR("config counter group set");

	/* get config counter groups */
	memset(&buf, 0, sizeof(buf));
	call.method = IB_MAD_METHOD_GET;

	if (!ib_vendor_call_via(&buf, portid, &call, srcport))
		IBERROR("config counter group query");
}

static int general_info, xmit_wait, counter_group_info, config_counter_group;

static int process_opt(void *context, int ch, char *optarg)
{
	int ret;
	switch (ch) {
	case 'N':
		general_info = 1;
		break;
	case 'w':
		xmit_wait = 1;
		break;
	case 'i':
		counter_group_info = 1;
		break;
	case 'c':
		config_counter_group = 1;
		ret = sscanf(optarg, "%d,%d", &cg0, &cg1);
		if (ret != 2)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int mgmt_classes[4] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS,
		IB_MLX_VENDOR_CLASS
	};
	ib_portid_t portid = { 0 };
	int port = 0;
	char buf[1024];
	ib_vendor_call_t call;
	is3_general_info_t *gi;
	is3_config_space_t *cs;
	int i;

	const struct ibdiag_opt opts[] = {
		{"N", 'N', 0, NULL, "show IS3 general information"},
		{"w", 'w', 0, NULL, "show IS3 port xmit wait counters"},
		{"i", 'i', 0, NULL, "show IS4 counter group info"},
		{"c", 'c', 1, "<num,num>", "configure IS4 counter groups"},
		{0}
	};

	char usage_args[] = "<lid|guid> [port]";
	const char *usage_examples[] = {
		"-N 6\t\t# read IS3 general information",
		"-w 6\t\t# read IS3 port xmit wait counters",
		"-i 6 12\t# read IS4 port 12 counter group info",
		"-c 0,1 6 12\t# configure IS4 port 12 counter groups for PortXmitDataSL",
		"-c 2,8 6 12\t# configure IS4 port 12 counter groups for PortRcvDataSL",
		NULL
	};

	ibdiag_process_opts(argc, argv, NULL, "D", opts, process_opt,
			    usage_args, usage_examples);

	argc -= optind;
	argv += optind;

	if (argc > 1)
		port = strtoul(argv[1], 0, 0);

	srcport = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 4);
	if (!srcport)
		IBERROR("Failed to open '%s' port '%d'", ibd_ca, ibd_ca_port);

	if (argc) {
		if (ib_resolve_portid_str_via(&portid, argv[0], ibd_dest_type,
					      ibd_sm_id, srcport) < 0)
			IBERROR("can't resolve destination port %s", argv[0]);
	} else {
		if (ib_resolve_self_via(&portid, &port, 0, srcport) < 0)
			IBERROR("can't resolve self port %s", argv[0]);
	}

	if (counter_group_info) {
		counter_groups_info(&portid, port);
		exit(0);
	}

	if (config_counter_group) {
		config_counter_groups(&portid, port);
		exit(0);
	}

	/* These are Mellanox specific vendor MADs */
	/* but vendors change the VendorId so how know for sure ? */
	/* Only General Info and Port Xmit Wait Counters */
	/* queries are currently supported */
	if (!general_info && !xmit_wait)
		IBERROR("at least one of -N and -w must be specified");

	/* Would need a list of these and it might not be complete */
	/* so for right now, punt on this */

	memset(&call, 0, sizeof(call));
	call.mgmt_class = IB_MLX_VENDOR_CLASS;
	call.method = IB_MAD_METHOD_GET;
	call.timeout = ibd_timeout;

	memset(&buf, 0, sizeof(buf));
	/* vendor ClassPortInfo is required attribute if class supported */
	call.attrid = CLASS_PORT_INFO;
	if (!ib_vendor_call_via(&buf, &portid, &call, srcport))
		IBERROR("classportinfo query");

	memset(&buf, 0, sizeof(buf));
	call.attrid = IB_MLX_IS3_GENERAL_INFO;
	if (!ib_vendor_call_via(&buf, &portid, &call, srcport))
		IBERROR("vendstat");
	gi = (is3_general_info_t *) & buf;

	if (general_info) {
		/* dump IS3 general info here */
		printf("hw_dev_rev:  0x%04x\n", ntohs(gi->hw_info.hw_revision));
		printf("hw_dev_id:   0x%04x\n", ntohs(gi->hw_info.device_id));
		printf("hw_uptime:   0x%08x\n", ntohl(gi->hw_info.uptime));
		printf("fw_version:  %02d.%02d.%02d\n",
		       gi->fw_info.major, gi->fw_info.minor,
		       gi->fw_info.sub_minor);
		printf("fw_build_id: 0x%04x\n", ntohl(gi->fw_info.build_id));
		printf("fw_date:     %02d/%02d/%04x\n",
		       gi->fw_info.month, gi->fw_info.day,
		       ntohs(gi->fw_info.year));
		printf("fw_psid:     '%s'\n", gi->fw_info.psid);
		printf("fw_ini_ver:  %d\n",
		       ntohl(gi->fw_info.ini_file_version));
		printf("sw_version:  %02d.%02d.%02d\n", gi->sw_info.major,
		       gi->sw_info.minor, gi->sw_info.sub_minor);
	}

	if (xmit_wait) {
		if (ntohs(gi->hw_info.device_id) != IS3_DEVICE_ID)
			IBERROR("Unsupported device ID 0x%x",
				ntohs(gi->hw_info.device_id));

		memset(&buf, 0, sizeof(buf));
		call.attrid = IB_MLX_IS3_CONFIG_SPACE_ACCESS;
		/* Limit of 18 accesses per MAD ? */
		call.mod = 2 << 22 | 16 << 16;	/* 16 records */
		/* Set record addresses for each port */
		cs = (is3_config_space_t *) & buf;
		for (i = 0; i < 16; i++)
			cs->record[i].address =
			    htonl(IB_MLX_IS3_PORT_XMIT_WAIT + ((i + 1) << 12));
		if (!ib_vendor_call_via(&buf, &portid, &call, srcport))
			IBERROR("vendstat");

		for (i = 0; i < 16; i++)
			if (cs->record[i].data)	/* PortXmitWait is 32 bit counter */
				printf("Port %d: PortXmitWait 0x%x\n", i + 4, ntohl(cs->record[i].data));	/* port 4 is first port */

		/* Last 8 ports is another query */
		memset(&buf, 0, sizeof(buf));
		call.attrid = IB_MLX_IS3_CONFIG_SPACE_ACCESS;
		call.mod = 2 << 22 | 8 << 16;	/* 8 records */
		/* Set record addresses for each port */
		cs = (is3_config_space_t *) & buf;
		for (i = 0; i < 8; i++)
			cs->record[i].address =
			    htonl(IB_MLX_IS3_PORT_XMIT_WAIT + ((i + 17) << 12));
		if (!ib_vendor_call_via(&buf, &portid, &call, srcport))
			IBERROR("vendstat");

		for (i = 0; i < 8; i++)
			if (cs->record[i].data)	/* PortXmitWait is 32 bit counter */
				printf("Port %d: PortXmitWait 0x%x\n",
				       i < 4 ? i + 21 : i - 3,
				       ntohl(cs->record[i].data));
	}

	mad_rpc_close_port(srcport);
	exit(0);
}
