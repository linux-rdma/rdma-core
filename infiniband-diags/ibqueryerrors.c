/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2008 Lawrence Livermore National Lab.  All rights reserved.
 * Copyright (c) 2009 HNR Consulting.  All rights reserved.
 * Copyright (c) 2010,2011 Mellanox Technologies LTD.  All rights reserved.
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

#include <config.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <util/node_name_map.h>
#include <infiniband/ibnetdisc.h>
#include <infiniband/mad.h>

#include "ibdiag_common.h"
#include "ibdiag_sa.h"

static struct ibmad_port *ibmad_port;
static char *node_name_map_file = NULL;
static nn_map_t *node_name_map = NULL;
static char *load_cache_file = NULL;
static uint16_t lid2sl_table[sizeof(uint8_t) * 1024 * 48] = { 0 };
static int obtain_sl = 1;

static int data_counters;
static int data_counters_only;
static int port_config;
static uint64_t port_guid;
static char *port_guid_str;
#define SUP_MAX 64
static int sup_total;
static enum MAD_FIELDS suppressed_fields[SUP_MAX];
static char *dr_path;
static uint8_t node_type_to_print;
static unsigned clear_errors, clear_counts, details;

#define PRINT_SWITCH 0x1
#define PRINT_CA     0x2
#define PRINT_ROUTER 0x4
#define PRINT_ALL 0xFF		/* all nodes default flag */

#define DEFAULT_HALF_WORLD_PR_TIMEOUT (3000)

static struct {
	int nodes_checked;
	int bad_nodes;
	int ports_checked;
	int bad_ports;
	int pma_query_failures;
} summary;

#define DEF_THRES_FILE IBDIAG_CONFIG_PATH"/error_thresholds"
static const char *threshold_file = DEF_THRES_FILE;

/* define a "packet" with threshold values in it */
static uint8_t thresholds[1204];
static char *threshold_str;

static unsigned valid_gid(ib_gid_t * gid)
{
	ib_gid_t zero_gid;
	memset(&zero_gid, 0, sizeof zero_gid);
	return memcmp(&zero_gid, gid, sizeof(*gid));
}

static void set_thres(char *name, uint64_t val)
{
	int f;
	int n;
	char tmp[256];
	for (f = IB_PC_EXT_ERR_SYM_F; f <= IB_PC_EXT_XMT_WAIT_F; f++) {
		if (strcmp(name, mad_field_name(f)) == 0) {
			mad_encode_field(thresholds, f, &val);
			snprintf(tmp, 255, "[%s = %" PRIu64 "]", name, val);
			threshold_str = realloc(threshold_str,
					strlen(threshold_str)+strlen(tmp)+1);
			if (!threshold_str) {
				fprintf(stderr, "Failed to allocate memory: "
					"%s\n", strerror(errno));
				exit(1);
			}
			n = strlen(threshold_str);
			strcpy(threshold_str+n, tmp);
		}
	}
}

static void set_thresholds(void)
{
	char buf[1024];
	uint64_t val = 0;
	FILE *thresf = fopen(threshold_file, "r");
	char *p_prefix, *p_last;
	char *name;
	char *val_str;
	char str[64];

	if (!thresf)
		return;

	snprintf(str, 63, "Thresholds: ");
	threshold_str = malloc(strlen(str)+1);
	if (!threshold_str) {
		fprintf(stderr, "Failed to allocate memory: %s\n",
			strerror(errno));
		exit(1);
	}
	strcpy(threshold_str, str);
	while (fgets(buf, sizeof buf, thresf) != NULL) {
		p_prefix = strtok_r(buf, "\n", &p_last);
		if (!p_prefix)
			continue; /* ignore blank lines */

		if (*p_prefix == '#')
			continue; /* ignore comment lines */

		name = strtok_r(p_prefix, "=", &p_last);
		val_str = strtok_r(NULL, "\n", &p_last);

		val = strtoul(val_str, NULL, 0);
		set_thres(name, val);
	}

	fclose(thresf);
}

static int exceeds_threshold(int field, uint64_t val)
{
	uint64_t thres = 0;
	mad_decode_field(thresholds, field, &thres);
	return (val > thres);
}

static void print_port_config(ibnd_node_t * node, int portnum)
{
	char width[64], speed[64], state[64], physstate[64];
	char remote_str[256];
	char link_str[256];
	char width_msg[256];
	char speed_msg[256];
	char ext_port_str[256];
	int iwidth, ispeed, fdr10, espeed, istate, iphystate, cap_mask;
	uint8_t *info;
	int rc;

	ibnd_port_t *port = node->ports[portnum];

	if (!port)
		return;

	iwidth = mad_get_field(port->info, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
	ispeed = mad_get_field(port->info, 0, IB_PORT_LINK_SPEED_ACTIVE_F);
	fdr10 = mad_get_field(port->ext_info, 0,
			      IB_MLNX_EXT_PORT_LINK_SPEED_ACTIVE_F) & FDR10;

	if (port->node->type == IB_NODE_SWITCH)
		info = (uint8_t *)&port->node->ports[0]->info;
	else
		info = (uint8_t *)&port->info;
	cap_mask = mad_get_field(info, 0, IB_PORT_CAPMASK_F);
	if (cap_mask & be32toh(IB_PORT_CAP_HAS_EXT_SPEEDS))
		espeed = mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_EXT_ACTIVE_F);
	else
		espeed = 0;
	istate = mad_get_field(port->info, 0, IB_PORT_STATE_F);
	iphystate = mad_get_field(port->info, 0, IB_PORT_PHYS_STATE_F);

	remote_str[0] = '\0';
	link_str[0] = '\0';
	width_msg[0] = '\0';
	speed_msg[0] = '\0';

	/* C14-24.2.1 states that a down port allows for invalid data to be
	 * returned for all PortInfo components except PortState and
	 * PortPhysicalState */
	if (istate != IB_LINK_DOWN) {
		if (!espeed) {
			if (fdr10)
				sprintf(speed, "10.0 Gbps (FDR10)");
			else
				mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F, speed,
					     64, &ispeed);
		} else
			mad_dump_val(IB_PORT_LINK_SPEED_EXT_ACTIVE_F, speed,
			     64, &espeed);

		snprintf(link_str, 256, "(%3s %18s %6s/%8s)",
			 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F, width, 64, &iwidth),
			 speed,
			 mad_dump_val(IB_PORT_STATE_F, state, 64, &istate),
			 mad_dump_val(IB_PORT_PHYS_STATE_F, physstate, 64, &iphystate));
	} else {
		snprintf(link_str, 256, "(              %6s/%8s)",
			 mad_dump_val(IB_PORT_STATE_F, state, 64, &istate),
			 mad_dump_val(IB_PORT_PHYS_STATE_F, physstate, 64, &iphystate));
	}

	if (port->remoteport) {
		char *rem_node_name = NULL;

		if (port->remoteport->ext_portnum)
			snprintf(ext_port_str, 256, "%d",
				 port->remoteport->ext_portnum);
		else
			ext_port_str[0] = '\0';

		get_max_msg(width_msg, speed_msg, 256, port);

		rem_node_name = remap_node_name(node_name_map,
						port->remoteport->node->guid,
						port->remoteport->node->
						nodedesc);

		rc = snprintf(remote_str, sizeof(remote_str),
			 "0x%016" PRIx64 " %6d %4d[%2s] \"%s\" (%s %s)\n",
			 port->remoteport->guid,
			 port->remoteport->base_lid ? port->remoteport->
			 base_lid : port->remoteport->node->smalid,
			 port->remoteport->portnum, ext_port_str, rem_node_name,
			 width_msg, speed_msg);
		if (rc > sizeof(remote_str))
			fprintf(stderr, "WARN: string buffer overflow\n");

		free(rem_node_name);
	} else
		snprintf(remote_str, 256, "           [  ] \"\" ( )\n");

	if (port->ext_portnum)
		snprintf(ext_port_str, 256, "%d", port->ext_portnum);
	else
		ext_port_str[0] = '\0';

	if (node->type == IB_NODE_SWITCH)
		printf("       Link info: %6d", node->smalid);
	else
		printf("       Link info: %6d", port->base_lid);

	printf("%4d[%2s] ==%s==>  %s",
	       port->portnum, ext_port_str, link_str, remote_str);
}

static int suppress(enum MAD_FIELDS field)
{
	int i = 0;
	for (i = 0; i < sup_total; i++)
		if (field == suppressed_fields[i])
			return 1;
	return 0;
}

static void report_suppressed(void)
{
	int i = 0;
	printf("## Suppressed:");
	for (i = 0; i < sup_total; i++)
		printf(" %s", mad_field_name(suppressed_fields[i]));
	printf("\n");
}

static int print_summary(void)
{
	printf("\n## Summary: %d nodes checked, %d bad nodes found\n",
		summary.nodes_checked, summary.bad_nodes);
	printf("##          %d ports checked, %d ports have errors beyond threshold\n",
		summary.ports_checked, summary.bad_ports);
	printf("## %s\n", threshold_str);
	if (summary.pma_query_failures)
		printf("##          %d PMA query failures\n", summary.pma_query_failures);
	report_suppressed();
	return (summary.bad_ports);
}

static void insert_lid2sl_table(struct sa_query_result *r)
{
    unsigned int i;
    for (i = 0; i < r->result_cnt; i++) {
	    ib_path_rec_t *p_pr = (ib_path_rec_t *)sa_get_query_rec(r->p_result_madw, i);
	    lid2sl_table[be16toh(p_pr->dlid)] = ib_path_rec_sl(p_pr);
    }
}

static int path_record_query(ib_gid_t sgid,uint64_t dguid)
{
     ib_path_rec_t pr;
     __be64 comp_mask = 0;
     uint8_t reversible = 0;
     struct sa_handle * h;

     if (!(h = sa_get_handle()))
	return -1;

     ibd_timeout = DEFAULT_HALF_WORLD_PR_TIMEOUT;
     memset(&pr, 0, sizeof(pr));

     CHECK_AND_SET_GID(sgid, pr.sgid, PR, SGID);
     if(dguid) {
	     mad_encode_field(sgid.raw, IB_GID_GUID_F, &dguid);
	     CHECK_AND_SET_GID(sgid, pr.dgid, PR, DGID);
     }

     CHECK_AND_SET_VAL(1, 8, -1, pr.num_path, PR, NUMBPATH);/*to get only one PathRecord for each source and destination pair*/
     CHECK_AND_SET_VAL(1, 8, -1, reversible, PR, REVERSIBLE);/*for a reversible path*/
     pr.num_path |= reversible << 7;
     struct sa_query_result result;
     int ret = sa_query(h, IB_MAD_METHOD_GET_TABLE,
                        (uint16_t)IB_SA_ATTR_PATHRECORD,0,be64toh(comp_mask),ibd_sakey,
                        &pr, sizeof(pr), &result);
     if (ret) {
             sa_free_handle(h);
             fprintf(stderr, "Query SA failed: %s; sa call path_query failed\n", strerror(ret));
             return ret;
     }
     if (result.status != IB_SA_MAD_STATUS_SUCCESS) {
             sa_report_err(result.status);
             ret = EIO;
             goto Exit;
     }

     insert_lid2sl_table(&result);
Exit:
     sa_free_handle(h);
     sa_free_result_mad(&result);
     return ret;
}

static int query_and_dump(char *buf, size_t size, ib_portid_t * portid,
			  char *node_name, int portnum,
			  const char *attr_name, uint16_t attr_id,
			  int start_field, int end_field)
{
	uint8_t pc[1024];
	uint32_t val = 0;
	int i, n;

	memset(pc, 0, sizeof(pc));

	if (!pma_query_via(pc, portid, portnum, ibd_timeout, attr_id,
			   ibmad_port)) {
		IBWARN("%s query failed on %s, %s port %d", attr_name,
		       node_name, portid2str(portid), portnum);
		summary.pma_query_failures++;
		return 0;
	}

	for (n = 0, i = start_field; i < end_field; i++) {
		mad_decode_field(pc, i, (void *)&val);
		if (val)
			n += snprintf(buf + n, size - n, " [%s == %u]",
				      mad_field_name(i), val);
	}

	return n;
}

static int check_threshold(uint8_t *pc, uint8_t *pce, uint32_t cap_mask2,
			 int i, int ext_i, int *n, char *str, size_t size)
{
	uint32_t val32 = 0;
	uint64_t val64 = 0;
	int is_exceeds = 0;
	float val = 0;
	const char *unit = "";

	if (htonl(cap_mask2) & IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP) {
		mad_decode_field(pce, ext_i, (void *)&val64);
		if (exceeds_threshold(ext_i, val64)) {
			unit = conv_cnt_human_readable(val64, &val, 0);
			*n += snprintf(str + *n, size - *n,
				       " [%s == %" PRIu64 " (%5.3f%s)]",
				       mad_field_name(ext_i), val64, val, unit);
			is_exceeds = 1;
		}

	} else {
		mad_decode_field(pc, i, (void *)&val32);
		if (exceeds_threshold(ext_i, val32)) {
			*n += snprintf(str + *n, size - *n, " [%s == %u]",
					  mad_field_name(i), val32);
			is_exceeds = 1;
		}
	}

	return is_exceeds;
}

static int print_results(ib_portid_t * portid, char *node_name,
			 ibnd_node_t * node, uint8_t * pc, int portnum,
			 int *header_printed, uint8_t *pce, __be16 cap_mask,
			 uint32_t cap_mask2)
{
	char buf[2048];
	char *str = buf;
	int i, ext_i, n;

	for (n = 0, i = IB_PC_ERR_SYM_F, ext_i = IB_PC_EXT_ERR_SYM_F;
			i <= IB_PC_VL15_DROPPED_F; i++, ext_i++ ) {
		if (suppress(i))
			continue;

		/* this is not a counter, skip it */
		if (i == IB_PC_COUNTER_SELECT2_F) {
			ext_i--;
			continue;
		}

		if (check_threshold(pc, pce, cap_mask2, i, ext_i, &n, str, sizeof(buf))) {

			/* If there are PortXmitDiscards, get details (if supported) */
			if (i == IB_PC_XMT_DISCARDS_F && details) {
				n += query_and_dump(str + n, sizeof(buf) - n, portid,
						    node_name, portnum,
						    "PortXmitDiscardDetails",
						    IB_GSI_PORT_XMIT_DISCARD_DETAILS,
						    IB_PC_RCV_LOCAL_PHY_ERR_F,
						    IB_PC_RCV_ERR_LAST_F);
				/* If there are PortRcvErrors, get details (if supported) */
			} else if (i == IB_PC_ERR_RCV_F && details) {
				n += query_and_dump(str + n, sizeof(buf) - n, portid,
						    node_name, portnum,
						    "PortRcvErrorDetails",
						    IB_GSI_PORT_RCV_ERROR_DETAILS,
						    IB_PC_XMT_INACT_DISC_F,
						    IB_PC_XMT_DISC_LAST_F);
			}
		}
	}

	if (!suppress(IB_PC_XMT_WAIT_F)) {
		check_threshold(pc, pce, cap_mask2, IB_PC_XMT_WAIT_F,
				IB_PC_EXT_XMT_WAIT_F, &n, str, sizeof(buf));
	}

	/* if we found errors. */
	if (n != 0) {
		if (data_counters) {
			uint8_t *pkt = pc;
			int start_field = IB_PC_XMT_BYTES_F;
			int end_field = IB_PC_RCV_PKTS_F;

			if (pce) {
				pkt = pce;
				start_field = IB_PC_EXT_XMT_BYTES_F;
				if (cap_mask & IB_PM_EXT_WIDTH_SUPPORTED)
					end_field = IB_PC_EXT_RCV_MPKTS_F;
				else
					end_field = IB_PC_EXT_RCV_PKTS_F;
			}

			for (i = start_field; i <= end_field; i++) {
				uint64_t val64 = 0;
				float val = 0;
				const char *unit = "";
				mad_decode_field(pkt, i, (void *)&val64);
				if (val64) {
					int data = 0;
					if (i == IB_PC_EXT_XMT_BYTES_F ||
					    i == IB_PC_EXT_RCV_BYTES_F ||
					    i == IB_PC_XMT_BYTES_F ||
					    i == IB_PC_RCV_BYTES_F)
						data = 1;
					unit = conv_cnt_human_readable(val64,
								&val, data);
					n += snprintf(str + n, sizeof(buf) - n,
						" [%s == %" PRIu64
						" (%5.3f%s)]",
						mad_field_name(i), val64, val,
						unit);
				}
			}
		}

		if (!*header_printed) {
			if (node->type == IB_NODE_SWITCH)
				printf("Errors for 0x%" PRIx64 " \"%s\"\n",
					node->ports[0]->guid, node_name);
			else
				printf("Errors for \"%s\"\n", node_name);
			*header_printed = 1;
			summary.bad_nodes++;
		}

		if (portnum == 0xFF) {
			if (node->type == IB_NODE_SWITCH)
				printf("   GUID 0x%" PRIx64 " port ALL:%s\n",
				       node->ports[0]->guid, str);
		} else {
			printf("   GUID 0x%" PRIx64 " port %d:%s\n",
			       node->ports[portnum]->guid, portnum, str);
			if (port_config)
				print_port_config(node, portnum);
			summary.bad_ports++;
		}
	}
	return (n);
}

static int query_cap_mask(ib_portid_t * portid, char *node_name, int portnum,
			  __be16 * cap_mask, uint32_t * cap_mask2)
{
	uint8_t pc[1024] = { 0 };
	__be16 rc_cap_mask;
	__be32 rc_cap_mask2;

	portid->sl = lid2sl_table[portid->lid];

	/* PerfMgt ClassPortInfo is a required attribute */
	if (!pma_query_via(pc, portid, portnum, ibd_timeout, CLASS_PORT_INFO,
			   ibmad_port)) {
		IBWARN("classportinfo query failed on %s, %s port %d",
		       node_name, portid2str(portid), portnum);
		summary.pma_query_failures++;
		return -1;
	}

	/* ClassPortInfo should be supported as part of libibmad */
	memcpy(&rc_cap_mask, pc + 2, sizeof(rc_cap_mask));	/* CapabilityMask */
	memcpy(&rc_cap_mask2, pc + 4, sizeof(rc_cap_mask2));	/* CapabilityMask2 */

	*cap_mask = rc_cap_mask;
	*cap_mask2 = ntohl(rc_cap_mask2) >> 5;
	return 0;
}

static int print_data_cnts(ib_portid_t * portid, __be16 cap_mask,
			   char *node_name, ibnd_node_t * node, int portnum,
			   int *header_printed)
{
	uint8_t pc[1024];
	int i;
	int start_field = IB_PC_XMT_BYTES_F;
	int end_field = IB_PC_RCV_PKTS_F;

	memset(pc, 0, 1024);

	portid->sl = lid2sl_table[portid->lid];

	if (cap_mask & (IB_PM_EXT_WIDTH_SUPPORTED | IB_PM_EXT_WIDTH_NOIETF_SUP)) {
		if (!pma_query_via(pc, portid, portnum, ibd_timeout,
				   IB_GSI_PORT_COUNTERS_EXT, ibmad_port)) {
			IBWARN("IB_GSI_PORT_COUNTERS_EXT query failed on %s, %s port %d",
			       node_name, portid2str(portid), portnum);
			summary.pma_query_failures++;
			return (1);
		}
		start_field = IB_PC_EXT_XMT_BYTES_F;
		if (cap_mask & IB_PM_EXT_WIDTH_SUPPORTED)
			end_field = IB_PC_EXT_RCV_MPKTS_F;
		else
			end_field = IB_PC_EXT_RCV_PKTS_F;
	} else {
		if (!pma_query_via(pc, portid, portnum, ibd_timeout,
				   IB_GSI_PORT_COUNTERS, ibmad_port)) {
			IBWARN("IB_GSI_PORT_COUNTERS query failed on %s, %s port %d",
			       node_name, portid2str(portid), portnum);
			summary.pma_query_failures++;
			return (1);
		}
		start_field = IB_PC_XMT_BYTES_F;
		end_field = IB_PC_RCV_PKTS_F;
	}

	if (!*header_printed) {
		printf("Data Counters for 0x%" PRIx64 " \"%s\"\n", node->guid,
		       node_name);
		*header_printed = 1;
	}

	if (portnum == 0xFF)
		printf("   GUID 0x%" PRIx64 " port ALL:", node->guid);
	else
		printf("   GUID 0x%" PRIx64 " port %d:",
		       node->guid, portnum);

	for (i = start_field; i <= end_field; i++) {
		uint64_t val64 = 0;
		float val = 0;
		const char *unit = "";
		int data = 0;
		mad_decode_field(pc, i, (void *)&val64);
		if (i == IB_PC_EXT_XMT_BYTES_F || i == IB_PC_EXT_RCV_BYTES_F ||
		    i == IB_PC_XMT_BYTES_F || i == IB_PC_RCV_BYTES_F)
			data = 1;
		unit = conv_cnt_human_readable(val64, &val, data);
		printf(" [%s == %" PRIu64 " (%5.3f%s)]", mad_field_name(i),
			val64, val, unit);
	}
	printf("\n");

	if (portnum != 0xFF && port_config)
		print_port_config(node, portnum);

	return (0);
}

static int print_errors(ib_portid_t * portid, __be16 cap_mask, uint32_t cap_mask2,
			char *node_name, ibnd_node_t * node, int portnum,
			int *header_printed)
{
	uint8_t pc[1024];
	uint8_t pce[1024];
	uint8_t *pc_ext = NULL;

	memset(pc, 0, 1024);
	memset(pce, 0, 1024);

	portid->sl = lid2sl_table[portid->lid];

	if (!pma_query_via(pc, portid, portnum, ibd_timeout,
			   IB_GSI_PORT_COUNTERS, ibmad_port)) {
		IBWARN("IB_GSI_PORT_COUNTERS query failed on %s, %s port %d",
		       node_name, portid2str(portid), portnum);
		summary.pma_query_failures++;
		return (0);
	}

	if (cap_mask & (IB_PM_EXT_WIDTH_SUPPORTED | IB_PM_EXT_WIDTH_NOIETF_SUP)) {
		if (!pma_query_via(pce, portid, portnum, ibd_timeout,
		    IB_GSI_PORT_COUNTERS_EXT, ibmad_port)) {
			IBWARN("IB_GSI_PORT_COUNTERS_EXT query failed on %s, %s port %d",
			       node_name, portid2str(portid), portnum);
			summary.pma_query_failures++;
			return (0);
		}
		pc_ext = pce;
	}

	if (!(cap_mask & IB_PM_PC_XMIT_WAIT_SUP)) {
		/* if PortCounters:PortXmitWait not supported clear this counter */
		uint32_t foo = 0;
		mad_encode_field(pc, IB_PC_XMT_WAIT_F, &foo);
	}
	return (print_results(portid, node_name, node, pc, portnum,
			      header_printed, pc_ext, cap_mask, cap_mask2));
}

static uint8_t *reset_pc_ext(void *rcvbuf, ib_portid_t *dest, int port,
			     unsigned mask, unsigned timeout,
			     const struct ibmad_port *srcport)
{
	ib_rpc_t rpc = { 0 };
	int lid = dest->lid;

	DEBUG("lid %u port %d mask 0x%x", lid, port, mask);

	if (lid == -1) {
		IBWARN("only lid routed is supported");
		return NULL;
	}

	if (!mask)
		mask = ~0;

	rpc.mgtclass = IB_PERFORMANCE_CLASS;
	rpc.method = IB_MAD_METHOD_SET;
	rpc.attr.id = IB_GSI_PORT_COUNTERS_EXT;

	memset(rcvbuf, 0, IB_MAD_SIZE);

	/* Same for attribute IDs */
	mad_set_field(rcvbuf, 0, IB_PC_EXT_PORT_SELECT_F, port);
	mad_set_field(rcvbuf, 0, IB_PC_EXT_COUNTER_SELECT_F, mask);
	mask = mask >> 16;
	mad_set_field(rcvbuf, 0, IB_PC_EXT_COUNTER_SELECT2_F, mask);
	rpc.attr.mod = 0;
	rpc.timeout = timeout;
	rpc.datasz = IB_PC_DATA_SZ;
	rpc.dataoffs = IB_PC_DATA_OFFS;
	if (!dest->qp)
		dest->qp = 1;
	if (!dest->qkey)
		dest->qkey = IB_DEFAULT_QP1_QKEY;

	return mad_rpc(srcport, &rpc, dest, rcvbuf, rcvbuf);
}

static void clear_port(ib_portid_t * portid, __be16 cap_mask, uint32_t cap_mask2,
		       char *node_name, int port)
{
	uint8_t pc[1024] = { 0 };
	/* bits defined in Table 228 PortCounters CounterSelect and
	 * CounterSelect2
	 */
	uint32_t mask = 0;

	if (clear_errors) {
		mask |= 0xFFF;
		if (cap_mask & IB_PM_PC_XMIT_WAIT_SUP)
			mask |= 0x10000;
	}
	if (clear_counts)
		mask |= 0xF000;

	if (mask)
		if (!performance_reset_via(pc, portid, port, mask, ibd_timeout,
					   IB_GSI_PORT_COUNTERS, ibmad_port))
			fprintf(stderr, "Failed to reset errors %s port %d\n", node_name,
				port);

	if (clear_errors && details) {
		memset(pc, 0, 1024);
		performance_reset_via(pc, portid, port, 0xf, ibd_timeout,
				      IB_GSI_PORT_XMIT_DISCARD_DETAILS,
				      ibmad_port);
		memset(pc, 0, 1024);
		performance_reset_via(pc, portid, port, 0x3f, ibd_timeout,
				      IB_GSI_PORT_RCV_ERROR_DETAILS,
				      ibmad_port);
	}

	if (cap_mask & (IB_PM_EXT_WIDTH_SUPPORTED | IB_PM_EXT_WIDTH_NOIETF_SUP)) {
		mask = 0;
		if (clear_counts) {
			if (cap_mask & IB_PM_EXT_WIDTH_SUPPORTED)
				mask = 0xFF;
			else
				mask = 0x0F;
		}

		if (clear_errors && (htonl(cap_mask2) & IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP)) {
			mask |= 0xfff0000;
			if (cap_mask & IB_PM_PC_XMIT_WAIT_SUP)
				mask |= (1 << 28);
		}

		if (mask && !reset_pc_ext(pc, portid, port, mask, ibd_timeout,
		    ibmad_port))
			fprintf(stderr, "Failed to reset extended data counters %s, "
				"%s port %d\n", node_name, portid2str(portid),
				port);
	}
}

static void print_node(ibnd_node_t *node, void *user_data)
{
	int header_printed = 0;
	int p = 0;
	int startport = 1;
	int type = 0;
	int all_port_sup = 0;
	ib_portid_t portid = { 0 };
	__be16 cap_mask = 0;
	uint32_t cap_mask2 = 0;
	char *node_name = NULL;

	switch (node->type) {
	case IB_NODE_SWITCH:
		type = PRINT_SWITCH;
		break;
	case IB_NODE_CA:
		type = PRINT_CA;
		break;
	case IB_NODE_ROUTER:
		type = PRINT_ROUTER;
		break;
	}

	if ((type & node_type_to_print) == 0)
		return;

	if (node->type == IB_NODE_SWITCH && node->smaenhsp0)
		startport = 0;

	node_name = remap_node_name(node_name_map, node->guid, node->nodedesc);

	if (node->type == IB_NODE_SWITCH) {
		ib_portid_set(&portid, node->smalid, 0, 0);
		p = 0;
	} else {
		for (p = 1; p <= node->numports; p++) {
			if (node->ports[p]) {
				ib_portid_set(&portid,
					      node->ports[p]->base_lid,
					      0, 0);
				break;
			}
		}
	}

	if ((query_cap_mask(&portid, node_name, p, &cap_mask, &cap_mask2) == 0) &&
	    (cap_mask & IB_PM_ALL_PORT_SELECT))
		all_port_sup = 1;

	if (data_counters_only) {
		for (p = startport; p <= node->numports; p++) {
			if (node->ports[p]) {
				if (node->type == IB_NODE_SWITCH)
					ib_portid_set(&portid, node->smalid, 0, 0);
				else
					ib_portid_set(&portid, node->ports[p]->base_lid,
						      0, 0);

				print_data_cnts(&portid, cap_mask, node_name, node, p,
						&header_printed);
				summary.ports_checked++;
				if (!all_port_sup)
					clear_port(&portid, cap_mask, cap_mask2, node_name, p);
			}
		}
	} else {
		if (all_port_sup)
			if (!print_errors(&portid, cap_mask, cap_mask2, node_name, node,
					  0xFF, &header_printed)) {
				summary.ports_checked += node->numports;
				goto clear;
			}

		for (p = startport; p <= node->numports; p++) {
			if (node->ports[p]) {
				if (node->type == IB_NODE_SWITCH)
					ib_portid_set(&portid, node->smalid, 0, 0);
				else
					ib_portid_set(&portid, node->ports[p]->base_lid,
						      0, 0);

				print_errors(&portid, cap_mask, cap_mask2, node_name, node, p,
					     &header_printed);
				summary.ports_checked++;
				if (!all_port_sup)
					clear_port(&portid, cap_mask, cap_mask2, node_name, p);
			}
		}
	}

clear:
	summary.nodes_checked++;
	if (all_port_sup)
		clear_port(&portid, cap_mask, cap_mask2, node_name, 0xFF);

	free(node_name);
}

static void add_suppressed(enum MAD_FIELDS field)
{
	if (sup_total >= SUP_MAX) {
		IBWARN("Maximum (%d) fields have been suppressed; skipping %s",
		       sup_total, mad_field_name(field));
		return;
	}
	suppressed_fields[sup_total++] = field;
}

static void calculate_suppressed_fields(char *str)
{
	enum MAD_FIELDS f;
	char *val, *lasts = NULL;
	char *tmp = strdup(str);

	val = strtok_r(tmp, ",", &lasts);
	while (val) {
		for (f = IB_PC_FIRST_F; f <= IB_PC_LAST_F; f++)
			if (strcmp(val, mad_field_name(f)) == 0)
				add_suppressed(f);
		val = strtok_r(NULL, ",", &lasts);
	}

	free(tmp);
}

static int process_opt(void *context, int ch)
{
	struct ibnd_config *cfg = context;
	switch (ch) {
	case 's':
		calculate_suppressed_fields(optarg);
		break;
	case 'c':
		/* Right now this is the only "common" error */
		add_suppressed(IB_PC_ERR_SWITCH_REL_F);
		break;
	case 1:
		node_name_map_file = strdup(optarg);
		if (node_name_map_file == NULL)
			IBEXIT("out of memory, strdup for node_name_map_file name failed");
		break;
	case 2:
		data_counters++;
		break;
	case 3:
		node_type_to_print |= PRINT_SWITCH;
		break;
	case 4:
		node_type_to_print |= PRINT_CA;
		break;
	case 5:
		node_type_to_print |= PRINT_ROUTER;
		break;
	case 6:
		details = 1;
		break;
	case 7:
		load_cache_file = strdup(optarg);
		break;
	case 8:
		threshold_file = strdup(optarg);
		break;
	case 9:
		data_counters_only = 1;
		break;
	case 10:
		obtain_sl = 0;
		break;
	case 'G':
	case 'S':
		port_guid_str = optarg;
		port_guid = strtoull(optarg, NULL, 0);
		break;
	case 'D':
		dr_path = strdup(optarg);
		break;
	case 'r':
		port_config++;
		break;
	case 'R':		/* nop */
		break;
	case 'k':
		clear_errors = 1;
		break;
	case 'K':
		clear_counts = 1;
		break;
	case 'o':
		cfg->max_smps = strtoul(optarg, NULL, 0);
		break;
	default:
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ibnd_config config = { 0 };
	int resolved = -1;
	ib_portid_t portid = { 0 };
	ib_portid_t self_portid = { 0 };
	int rc = 0;
	ibnd_fabric_t *fabric = NULL;
	ib_gid_t self_gid;
	int port = 0;

	int mgmt_classes[4] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS,
		IB_PERFORMANCE_CLASS
	};

	const struct ibdiag_opt opts[] = {
		{"suppress", 's', 1, "<err1,err2,...>",
		 "suppress errors listed"},
		{"suppress-common", 'c', 0, NULL,
		 "suppress some of the common counters"},
		{"node-name-map", 1, 1, "<file>", "node name map file"},
		{"port-guid", 'G', 1, "<port_guid>",
		 "report the node containing the port specified by <port_guid>"},
		{"", 'S', 1, "<port_guid>",
		 "Same as \"-G\" for backward compatibility"},
		{"Direct", 'D', 1, "<dr_path>",
		 "report the node containing the port specified by <dr_path>"},
		{"skip-sl", 10, 0, NULL,"don't obtain SL to all destinations"},
		{"report-port", 'r', 0, NULL,
		 "report port link information"},
		{"threshold-file", 8, 1, NULL,
		 "specify an alternate threshold file, default: " DEF_THRES_FILE},
		{"GNDN", 'R', 0, NULL,
		 "(This option is obsolete and does nothing)"},
		{"data", 2, 0, NULL, "include data counters for ports with errors"},
		{"switch", 3, 0, NULL, "print data for switches only"},
		{"ca", 4, 0, NULL, "print data for CA's only"},
		{"router", 5, 0, NULL, "print data for routers only"},
		{"details", 6, 0, NULL, "include transmit discard details"},
		{"counters", 9, 0, NULL, "print data counters only"},
		{"clear-errors", 'k', 0, NULL,
		 "Clear error counters after read"},
		{"clear-counts", 'K', 0, NULL,
		 "Clear data counters after read"},
		{"load-cache", 7, 1, "<file>",
		 "filename of ibnetdiscover cache to load"},
		{"outstanding_smps", 'o', 1, NULL,
		 "specify the number of outstanding SMP's which should be "
		 "issued during the scan"},
		{}
	};
	char usage_args[] = "";

	memset(suppressed_fields, 0, sizeof suppressed_fields);
	ibdiag_process_opts(argc, argv, &config, "cDGKLnRrSs", opts, process_opt,
			    usage_args, NULL);

	argc -= optind;
	argv += optind;

	if (!node_type_to_print)
		node_type_to_print = PRINT_ALL;

	ibmad_port = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 4);
	if (!ibmad_port)
		IBEXIT("Failed to open port; %s:%d\n", ibd_ca, ibd_ca_port);

	smp_mkey_set(ibmad_port, ibd_mkey);

	if (ibd_timeout) {
		mad_rpc_set_timeout(ibmad_port, ibd_timeout);
		config.timeout_ms = ibd_timeout;
	}

	config.flags = ibd_ibnetdisc_flags;
	config.mkey = ibd_mkey;

	if (dr_path && load_cache_file) {
		mad_rpc_close_port(ibmad_port);
		fprintf(stderr, "Cannot specify cache and direct route path\n");
		exit(-1);
	}

	if (resolve_self(ibd_ca, ibd_ca_port, &self_portid, &port, &self_gid.raw) < 0) {
		mad_rpc_close_port(ibmad_port);
		IBEXIT("can't resolve self port %s", argv[0]);
	}

	node_name_map = open_node_name_map(node_name_map_file);

	/* limit the scan the fabric around the target */
	if (dr_path) {
		if ((resolved =
		     resolve_portid_str(ibd_ca, ibd_ca_port, &portid, dr_path,
					IB_DEST_DRPATH, NULL, ibmad_port)) < 0)
			IBWARN("Failed to resolve %s; attempting full scan",
			       dr_path);
	} else if (port_guid_str) {
		if ((resolved =
		     resolve_portid_str(ibd_ca, ibd_ca_port, &portid,
					port_guid_str, IB_DEST_GUID, ibd_sm_id,
					       ibmad_port)) < 0)
			IBWARN("Failed to resolve %s; attempting full scan",
			       port_guid_str);
		if(obtain_sl)
			lid2sl_table[portid.lid] = portid.sl;
	}

	mad_rpc_close_port(ibmad_port);

	if (load_cache_file) {
		if ((fabric = ibnd_load_fabric(load_cache_file, 0)) == NULL) {
			fprintf(stderr, "loading cached fabric failed\n");
			rc = -1;
			goto close_name_map;
		}
	} else {
		if (resolved >= 0) {
			if (!config.max_hops)
				config.max_hops = 1;
			if (!(fabric = ibnd_discover_fabric(ibd_ca, ibd_ca_port,
						    &portid, &config)))
				IBWARN("Single node discover failed;"
				       " attempting full scan");
		}

		if (!fabric && !(fabric = ibnd_discover_fabric(ibd_ca,
							       ibd_ca_port,
							       NULL,
							       &config))) {
			fprintf(stderr, "discover failed\n");
			rc = -1;
			goto close_name_map;
		}
	}

	set_thresholds();

	/* reopen the global ibmad_port */
	ibmad_port = mad_rpc_open_port(ibd_ca, ibd_ca_port,
				       mgmt_classes, 4);
	if (!ibmad_port) {
		ibnd_destroy_fabric(fabric);
		close_node_name_map(node_name_map);
		IBEXIT("Failed to reopen port: %s:%d\n",
			ibd_ca, ibd_ca_port);
	}

	smp_mkey_set(ibmad_port, ibd_mkey);

	if (ibd_timeout)
		mad_rpc_set_timeout(ibmad_port, ibd_timeout);

	if (port_guid_str) {
		ibnd_port_t *ndport = ibnd_find_port_guid(fabric, port_guid);
		if (ndport)
			print_node(ndport->node, NULL);
		else
			fprintf(stderr, "Failed to find node: %s\n",
				port_guid_str);
	} else if (dr_path) {
		ibnd_port_t *ndport;

		uint8_t ni[IB_SMP_DATA_SIZE] = { 0 };
		if (!smp_query_via(ni, &portid, IB_ATTR_NODE_INFO, 0,
			   ibd_timeout, ibmad_port)) {
				fprintf(stderr, "Failed to query local Node Info\n");
				goto close_port;
		}

		mad_decode_field(ni, IB_NODE_PORT_GUID_F, &(port_guid));

		ndport = ibnd_find_port_guid(fabric, port_guid);
		if (ndport) {
			if(obtain_sl)
				if(path_record_query(self_gid,ndport->guid))
					goto close_port;
			print_node(ndport->node, NULL);
		} else
			fprintf(stderr, "Failed to find node: %s\n", dr_path);
	} else {
		if(obtain_sl)
			if(path_record_query(self_gid,0))
				goto close_port;

		ibnd_iter_nodes(fabric, print_node, NULL);
	}

	rc = print_summary();
	if (rc)
		rc = 1;

close_port:
	mad_rpc_close_port(ibmad_port);
	ibnd_destroy_fabric(fabric);

close_name_map:
	close_node_name_map(node_name_map);
	exit(rc);
}
