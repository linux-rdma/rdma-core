/*
 * Copyright (c) 2006,2007 The Regents of the University of California.
 * Copyright (c) 2004-2007 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2005 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 *
 * Produced at Lawrence Livermore National Laboratory.
 * Written by Ira Weiny <weiny2@llnl.gov>.
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>

#define _GNU_SOURCE
#include <getopt.h>

#define __BUILD_VERSION_TAG__ 1.2.4

#include <infiniband/opensm/osm_log.h>
#include <infiniband/vendor/osm_vendor_api.h>
#include <infiniband/vendor/osm_vendor_sa_api.h>
#include <infiniband/opensm/osm_mad_pool.h>
#include <infiniband/complib/cl_debug.h>

#include "ibdiag_common.h"

char *argv0 = "saquery";

static char *switch_map = NULL;
static FILE *switch_map_fp = NULL;

/**
 * Declare some globals because I don't want this to be too complex.
 */
#define MAX_PORTS (8)
#define DEFAULT_SA_TIMEOUT_MS (1000)
osmv_query_res_t   result;
osm_log_t          log_osm;
osm_mad_pool_t     mad_pool;
osm_vendor_t      *vendor = NULL;
int                osm_debug = 0;
uint32_t           sa_timeout_ms = DEFAULT_SA_TIMEOUT_MS;

enum {
	ALL,
	LID_ONLY,
	UNIQUE_LID_ONLY,
	GUID_ONLY,
	ALL_DESC,
	NAME_OF_LID,
	NAME_OF_GUID,
} node_print_desc = ALL;

char              *requested_name = NULL;
ib_net16_t         requested_lid = 0;
int                requested_lid_flag = 0;
ib_net64_t         requested_guid = 0;
int                requested_guid_flag = 0;
ib_net16_t         query_type = IB_MAD_ATTR_NODE_RECORD;

/**
 * Call back for the various record requests.
 */
static void
query_res_cb(osmv_query_res_t *res)
{
	result = *res;
}

static void
print_node_desc(ib_node_record_t *node_record)
{
	ib_node_info_t *p_ni = &(node_record->node_info);
	ib_node_desc_t *p_nd = &(node_record->node_desc);

	if (p_ni->node_type == IB_NODE_TYPE_CA)
	{
		printf("%6d  \"%s\"\n",
		       cl_ntoh16(node_record->lid),
		       clean_nodedesc((char *)p_nd->description));
	}
}

static void
print_node_record(ib_node_record_t *node_record)
{
	ib_node_info_t *p_ni = NULL;
	ib_node_desc_t *p_nd = NULL;
	char *name;

	p_ni = &(node_record->node_info);
        p_nd = &(node_record->node_desc);

	switch (node_print_desc) {
	case LID_ONLY:
	case UNIQUE_LID_ONLY:
		printf("%d\n", cl_ntoh16(node_record->lid));
		return;
	case GUID_ONLY:
		printf("0x%016" PRIx64 "\n", cl_ntoh64(p_ni->port_guid));
		return;
	case NAME_OF_LID:
	case NAME_OF_GUID:
		if (p_ni->node_type == IB_NODE_TYPE_SWITCH)
			name = lookup_switch_name(switch_map_fp,
						  cl_ntoh64(p_ni->node_guid),
						  p_nd->description);
		else
			name = clean_nodedesc((char *)p_nd->description);
		printf("%s\n", name);
		return;
	case ALL:
	default:
		break;
        }

	printf("NodeRecord dump:\n"
	       "\t\tlid.....................0x%X\n"
	       "\t\treserved................0x%X\n"
	       "\t\tbase_version............0x%X\n"
	       "\t\tclass_version...........0x%X\n"
	       "\t\tnode_type...............%s\n"
	       "\t\tnum_ports...............0x%X\n"
	       "\t\tsys_guid................0x%016" PRIx64 "\n"
	       "\t\tnode_guid...............0x%016" PRIx64 "\n"
	       "\t\tport_guid...............0x%016" PRIx64 "\n"
	       "\t\tpartition_cap...........0x%X\n"
	       "\t\tdevice_id...............0x%X\n"
	       "\t\trevision................0x%X\n"
	       "\t\tport_num................0x%X\n"
	       "\t\tvendor_id...............0x%X\n"
	       "\t\tNodeDescription.........%s\n"
	       "",
	       cl_ntoh16(node_record->lid),
	       cl_ntoh16(node_record->resv),
	       p_ni->base_version,
	       p_ni->class_version,
	       ib_get_node_type_str( p_ni->node_type ),
	       p_ni->num_ports,
	       cl_ntoh64( p_ni->sys_guid ),
	       cl_ntoh64( p_ni->node_guid ),
	       cl_ntoh64( p_ni->port_guid ),
	       cl_ntoh16( p_ni->partition_cap ),
	       cl_ntoh16( p_ni->device_id ),
	       cl_ntoh32( p_ni->revision ),
	       ib_node_info_get_local_port_num( p_ni ),
	       cl_ntoh32( ib_node_info_get_vendor_id( p_ni )),
	       clean_nodedesc((char *)node_record->node_desc.description)
	       );
}

static void
print_path_record(ib_path_rec_t *p_pr)
{
	printf("PathRecord dump:\n"
	       "\t\tresv0...................0x%016" PRIx64 "\n"
	       "\t\tdgid....................0x%016" PRIx64 " : "
	       "0x%016" PRIx64 "\n"
	       "\t\tsgid....................0x%016" PRIx64 " : "
	       "0x%016" PRIx64 "\n"
	       "\t\tdlid....................0x%X\n"
	       "\t\tslid....................0x%X\n"
	       "\t\thop_flow_raw............0x%X\n"
	       "\t\ttclass..................0x%X\n"
	       "\t\tnum_path_revers.........0x%X\n"
	       "\t\tpkey....................0x%X\n"
	       "\t\tsl......................0x%X\n"
	       "\t\tmtu.....................0x%X\n"
	       "\t\trate....................0x%X\n"
	       "\t\tpkt_life................0x%X\n"
	       "\t\tpreference..............0x%X\n"
	       "\t\tresv2...................0x%X\n"
	       "\t\tresv3...................0x%X\n"
	       "",
	       *(uint64_t*)p_pr->resv0,
	       cl_ntoh64( p_pr->dgid.unicast.prefix ),
	       cl_ntoh64( p_pr->dgid.unicast.interface_id ),
	       cl_ntoh64( p_pr->sgid.unicast.prefix ),
	       cl_ntoh64( p_pr->sgid.unicast.interface_id ),
	       cl_ntoh16( p_pr->dlid ),
	       cl_ntoh16( p_pr->slid ),
	       cl_ntoh32( p_pr->hop_flow_raw ),
	       p_pr->tclass,
	       p_pr->num_path,
	       cl_ntoh16( p_pr->pkey ),
	       cl_ntoh16( p_pr->sl ),
	       p_pr->mtu,
	       p_pr->rate,
	       p_pr->pkt_life,
	       p_pr->preference,
	       *(uint32_t*)&p_pr->resv2,
	       *((uint16_t*)&p_pr->resv2 + 2)
	       );
}

/**
 * str must be longer than 32 to hold the full gid.
 * len will be checked to ensure this.
 */
static char *
sprint_gid(ib_gid_t *gid, char *str, size_t len)
{
	int  i = 0;
	char tmp[16];

	assert(str != NULL);
	assert(len > 32);

	str[0] = '\0';
	for (i = 0; i < 16; i++) {
		sprintf(tmp, "%02X", gid->raw[i]);
		strcat(str, tmp);
	}

	return (str);
}

static void
print_class_port_info(ib_class_port_info_t *class_port_info)
{
	size_t GID_STR_LEN = 256;
	char   gid_str[GID_STR_LEN];

	printf("SA ClassPortInfo:\n"
	       "\t\tBase version.............%d\n"
	       "\t\tClass version............%d\n"
	       "\t\tCapability mask..........0x%04X\n"
	       "\t\tResponse time value......0x%08X\n"
	       "\t\tRedirect GID.............0x%s\n"
	       "\t\tRedirect TC/SL/FL........0x%08X\n"
	       "\t\tRedirect LID.............0x%04X\n"
	       "\t\tRedirect PKey............0x%04X\n"
	       "\t\tRedirect QP..............0x%08X\n"
	       "\t\tRedirect QKey............0x%08X\n"
	       "\t\tTrap GID.................0x%s\n"
	       "\t\tTrap TC/SL/FL............0x%08X\n"
	       "\t\tTrap LID.................0x%04X\n"
	       "\t\tTrap PKey................0x%04X\n"
	       "\t\tTrap HL/QP...............0x%08X\n"
	       "\t\tTrap QKey................0x%08X\n"
	       "",
	       class_port_info->base_ver,
	       class_port_info->class_ver,
	       cl_ntoh16(class_port_info->cap_mask),
	       class_port_info->resp_time_val,
	       sprint_gid(&(class_port_info->redir_gid), gid_str, GID_STR_LEN),
	       cl_ntoh32(class_port_info->redir_tc_sl_fl),
	       cl_ntoh16(class_port_info->redir_lid),
	       cl_ntoh16(class_port_info->redir_pkey),
	       cl_ntoh32(class_port_info->redir_qp),
	       cl_ntoh32(class_port_info->redir_qkey),
	       sprint_gid(&(class_port_info->trap_gid), gid_str, GID_STR_LEN),
	       cl_ntoh32(class_port_info->trap_tc_sl_fl),
	       cl_ntoh16(class_port_info->trap_lid),
	       cl_ntoh16(class_port_info->trap_pkey),
	       cl_ntoh32(class_port_info->trap_hop_qp),
	       cl_ntoh32(class_port_info->trap_qkey)
	      );
}

static void
print_portinfo_record(ib_portinfo_record_t *p_pir)
{
	const ib_port_info_t * const p_pi = &p_pir->port_info;

        printf("PortInfoRecord dump:\n"
	       "\t\tEndPortLid..............0x%X\n"
	       "\t\tPortNum.................0x%X\n"
	       "\t\tbase_lid................0x%X\n"
	       "\t\tmaster_sm_base_lid......0x%X\n"
	       "\t\tcapability_mask.........0x%X\n"
	       "",
	       cl_ntoh16(p_pir->lid),
	       p_pir->port_num,
	       cl_ntoh16( p_pi->base_lid ),
	       cl_ntoh16( p_pi->master_sm_base_lid ),
	       cl_ntoh32( p_pi->capability_mask )
               );
}

static void
print_multicast_group_record(ib_member_rec_t *p_mcmr)
{
	printf("MCMemberRecord group dump:\n"
	       "\t\tMGID....................0x%016" PRIx64 " : "
	       "0x%016" PRIx64 "\n"
	       "\t\tMlid....................0x%X\n"
	       "\t\tMtu.....................0x%X\n"
	       "\t\tpkey....................0x%X\n"
	       "\t\tRate....................0x%X\n"
	       "",
	       cl_ntoh64( p_mcmr->mgid.unicast.prefix ),
	       cl_ntoh64( p_mcmr->mgid.unicast.interface_id ),
	       cl_ntoh16( p_mcmr->mlid ),
	       p_mcmr->mtu,
	       cl_ntoh16( p_mcmr->pkey ),
	       p_mcmr->rate
	       );
}

static void
print_multicast_member_record(ib_member_rec_t *p_mcmr)
{
	uint64_t gid_prefix = cl_ntoh64( p_mcmr->port_gid.unicast.prefix );
	uint64_t gid_interface_id = cl_ntoh64( p_mcmr->port_gid.unicast.interface_id );
	uint16_t mlid = cl_ntoh16( p_mcmr->mlid );
	ib_node_record_t *node_record = NULL;
	int      i = 0;

	/* go through and find the node description for this node GID */
	for (i = 0; i < result.result_cnt; i++) {
		node_record = osmv_get_query_node_rec(result.p_result_madw, i);
		if (cl_ntoh64(node_record->node_info.port_guid) == gid_interface_id)
			break;
	}

	if (requested_name) {
		if (strtol(requested_name, NULL, 0) == mlid) {
			printf("\t\tPortGid.................0x%016" PRIx64 " : "
			       "0x%016" PRIx64 " (%s)\n",
			       gid_prefix,
			       gid_interface_id,
			       clean_nodedesc((char *)node_record->node_desc.description)
			      );
		}
	} else {
		printf("MCMemberRecord member dump:\n"
		       "\t\tMGID....................0x%016" PRIx64 " : "
		       "0x%016" PRIx64 "\n"
		       "\t\tMlid....................0x%X\n"
		       "\t\tPortGid.................0x%016" PRIx64 " : "
		       "0x%016" PRIx64 "\n"
		       "\t\tScopeState..............0x%X\n"
		       "\t\tProxyJoin...............0x%X\n"
		       "\t\tNodeDescription.........%s\n"
		       "",
		       cl_ntoh64( p_mcmr->mgid.unicast.prefix ),
		       cl_ntoh64( p_mcmr->mgid.unicast.interface_id ),
		       cl_ntoh16( p_mcmr->mlid ),
		       gid_prefix,
		       gid_interface_id,
		       p_mcmr->scope_state,
		       p_mcmr->proxy_join,
		       clean_nodedesc((char *)node_record->node_desc.description)
		      );
	}
}

static void
print_service_record(ib_service_record_t *p_sr)
{
	char buf_service_key[35];
	char buf_service_name[65];

	sprintf(buf_service_key,
		"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		p_sr->service_key[0],
		p_sr->service_key[1],
		p_sr->service_key[2],
		p_sr->service_key[3],
		p_sr->service_key[4],
		p_sr->service_key[5],
		p_sr->service_key[6],
		p_sr->service_key[7],
		p_sr->service_key[8],
		p_sr->service_key[9],
		p_sr->service_key[10],
		p_sr->service_key[11],
		p_sr->service_key[12],
		p_sr->service_key[13],
		p_sr->service_key[14],
		p_sr->service_key[15]);
	strncpy(buf_service_name, (char *)p_sr->service_name, 64);
	buf_service_name[64] = '\0';

	printf("ServiceRecord dump:\n"
	       "\t\tServiceID...............0x%016" PRIx64 "\n"
	       "\t\tServiceGID..............0x%016" PRIx64 " : "
	       "0x%016" PRIx64 "\n"
	       "\t\tServiceP_Key............0x%X\n"
	       "\t\tServiceLease............0x%X\n"
	       "\t\tServiceKey..............%s\n"
	       "\t\tServiceName.............%s\n"
	       "\t\tServiceData8.1..........0x%X\n"
	       "\t\tServiceData8.2..........0x%X\n"
	       "\t\tServiceData8.3..........0x%X\n"
	       "\t\tServiceData8.4..........0x%X\n"
	       "\t\tServiceData8.5..........0x%X\n"
	       "\t\tServiceData8.6..........0x%X\n"
	       "\t\tServiceData8.7..........0x%X\n"
	       "\t\tServiceData8.8..........0x%X\n"
	       "\t\tServiceData8.9..........0x%X\n"
	       "\t\tServiceData8.10.........0x%X\n"
	       "\t\tServiceData8.11.........0x%X\n"
	       "\t\tServiceData8.12.........0x%X\n"
	       "\t\tServiceData8.13.........0x%X\n"
	       "\t\tServiceData8.14.........0x%X\n"
	       "\t\tServiceData8.15.........0x%X\n"
	       "\t\tServiceData8.16.........0x%X\n"
	       "\t\tServiceData16.1.........0x%X\n"
	       "\t\tServiceData16.2.........0x%X\n"
	       "\t\tServiceData16.3.........0x%X\n"
	       "\t\tServiceData16.4.........0x%X\n"
	       "\t\tServiceData16.5.........0x%X\n"
	       "\t\tServiceData16.6.........0x%X\n"
	       "\t\tServiceData16.7.........0x%X\n"
	       "\t\tServiceData16.8.........0x%X\n"
	       "\t\tServiceData32.1.........0x%X\n"
	       "\t\tServiceData32.2.........0x%X\n"
	       "\t\tServiceData32.3.........0x%X\n"
	       "\t\tServiceData32.4.........0x%X\n"
	       "\t\tServiceData64.1.........0x%016" PRIx64 "\n"
	       "\t\tServiceData64.2.........0x%016" PRIx64 "\n"
	       "",
	       cl_ntoh64( p_sr->service_id ),
	       cl_ntoh64( p_sr->service_gid.unicast.prefix ),
	       cl_ntoh64( p_sr->service_gid.unicast.interface_id ),
	       cl_ntoh16( p_sr->service_pkey ),
	       cl_ntoh32( p_sr->service_lease ),
	       buf_service_key,
	       buf_service_name,
	       p_sr->service_data8[0], p_sr->service_data8[1],
	       p_sr->service_data8[2], p_sr->service_data8[3],
	       p_sr->service_data8[4], p_sr->service_data8[5],
	       p_sr->service_data8[6], p_sr->service_data8[7],
	       p_sr->service_data8[8], p_sr->service_data8[9],
	       p_sr->service_data8[10], p_sr->service_data8[11],
	       p_sr->service_data8[12], p_sr->service_data8[13],
	       p_sr->service_data8[14], p_sr->service_data8[15],
	       cl_ntoh16( p_sr->service_data16[0] ),
	       cl_ntoh16( p_sr->service_data16[1] ),
	       cl_ntoh16( p_sr->service_data16[2] ),
	       cl_ntoh16( p_sr->service_data16[3] ),
	       cl_ntoh16( p_sr->service_data16[4] ),
	       cl_ntoh16( p_sr->service_data16[5] ),
	       cl_ntoh16( p_sr->service_data16[6] ),
	       cl_ntoh16( p_sr->service_data16[7] ),
	       cl_ntoh32( p_sr->service_data32[0] ),
	       cl_ntoh32( p_sr->service_data32[1] ),
	       cl_ntoh32( p_sr->service_data32[2] ),
	       cl_ntoh32( p_sr->service_data32[3] ),
	       cl_ntoh64( p_sr->service_data64[0] ),
	       cl_ntoh64( p_sr->service_data64[1] )
	      );
}

static void
print_inform_info_record(ib_inform_info_record_t *p_iir)
{
	uint32_t qpn;
	uint8_t  resp_time_val;

	ib_inform_info_get_qpn_resp_time(p_iir->inform_info.g_or_v.generic.qpn_resp_time_val, &qpn, &resp_time_val);

	if (p_iir->inform_info.is_generic) {
		printf("InformInfoRecord dump:\n"
		       "\t\tRID\n"
		       "\t\tSubscriberGID...........0x%016" PRIx64 " : "
		       "0x%016" PRIx64 "\n"
		       "\t\tSubscriberEnum..........0x%X\n"
		       "\t\tInformInfo dump:\n"
		       "\t\tgid.....................0x%016" PRIx64 " : 0x%016" PRIx64 "\n"
		       "\t\tlid_range_begin.........0x%X\n"
		       "\t\tlid_range_end...........0x%X\n"
		       "\t\tis_generic..............0x%X\n"
		       "\t\tsubscribe...............0x%X\n"
		       "\t\ttrap_type...............0x%X\n"
		       "\t\ttrap_num................%u\n"
		       "\t\tqpn.....................0x%06X\n"
		       "\t\tresp_time_val...........0x%X\n"
		       "\t\tnode_type...............0x%06X\n"
		       "",
		       cl_ntoh64( p_iir->subscriber_gid.unicast.prefix ),
		       cl_ntoh64( p_iir->subscriber_gid.unicast.interface_id ),
		       cl_ntoh16( p_iir->subscriber_enum ),
		       cl_ntoh64( p_iir->inform_info.gid.unicast.prefix ),
		       cl_ntoh64( p_iir->inform_info.gid.unicast.interface_id ),
		       cl_ntoh16( p_iir->inform_info.lid_range_begin ),
		       cl_ntoh16( p_iir->inform_info.lid_range_end ),
		       p_iir->inform_info.is_generic,
		       p_iir->inform_info.subscribe,
		       cl_ntoh16( p_iir->inform_info.trap_type ),
		       cl_ntoh16( p_iir->inform_info.g_or_v.generic.trap_num ),
		       cl_ntoh32( qpn ),
		       resp_time_val,
		       cl_ntoh32(ib_inform_info_get_prod_type( &p_iir->inform_info ))
		      );
	} else {
		printf("InformInfoRecord dump:\n"
		       "\t\tRID\n"
		       "\t\tSubscriberGID...........0x%016" PRIx64 " : "
		       "0x%016" PRIx64 "\n"
		       "\t\tSubscriberEnum..........0x%X\n"
		       "\t\tInformInfo dump:\n"
		       "\t\tgid.....................0x%016" PRIx64 " : 0x%016" PRIx64 "\n"
		       "\t\tlid_range_begin.........0x%X\n"
		       "\t\tlid_range_end...........0x%X\n"
		       "\t\tis_generic..............0x%X\n"
		       "\t\tsubscribe...............0x%X\n"
		       "\t\ttrap_type...............0x%X\n"
		       "\t\tdev_id..................0x%X\n"
		       "\t\tqpn.....................0x%06X\n"
		       "\t\tresp_time_val...........0x%X\n"
		       "\t\tvendor_id...............0x%06X\n"
		       "",
		       cl_ntoh64( p_iir->subscriber_gid.unicast.prefix ),
		       cl_ntoh64( p_iir->subscriber_gid.unicast.interface_id ),
		       cl_ntoh16( p_iir->subscriber_enum ),
		       cl_ntoh64( p_iir->inform_info.gid.unicast.prefix ),
		       cl_ntoh64( p_iir->inform_info.gid.unicast.interface_id ),
		       cl_ntoh16( p_iir->inform_info.lid_range_begin ),
		       cl_ntoh16( p_iir->inform_info.lid_range_end ),
		       p_iir->inform_info.is_generic,
		       p_iir->inform_info.subscribe,
		       cl_ntoh16( p_iir->inform_info.trap_type ),
		       cl_ntoh16( p_iir->inform_info.g_or_v.vend.dev_id ),
		       cl_ntoh32( qpn ),
		       resp_time_val,
		       cl_ntoh32(ib_inform_info_get_prod_type( &p_iir->inform_info ))
		      );
	}
}

static void
return_mad(void)
{
	/*
	 * Return the IB query MAD to the pool as necessary.
	 */
	if (result.p_result_madw != NULL) {
		osm_mad_pool_put(&mad_pool, result.p_result_madw);
		result.p_result_madw = NULL;
	}
}

/**
 * Get all the records available for requested query type.
 */
static ib_api_status_t
get_all_records(osm_bind_handle_t bind_handle,
		ib_net16_t query_id,
		ib_net16_t attr_offset,
		int trusted)
{
	ib_api_status_t   status;
	osmv_query_req_t  req;
	osmv_user_query_t user;

	memset( &req, 0, sizeof( req ) );
	memset( &user, 0, sizeof( user ) );

	user.attr_id = query_id;
	user.attr_offset = attr_offset;

	req.query_type = OSMV_QUERY_USER_DEFINED;
	req.timeout_ms = sa_timeout_ms;
	req.retry_cnt = 1;
	req.flags = OSM_SA_FLAGS_SYNC;
	req.query_context = NULL;
	req.pfn_query_cb = query_res_cb;
	req.p_query_input = &user;
	if (trusted)
		req.sm_key = OSM_DEFAULT_SM_KEY;
	else
		req.sm_key = 0;

	if ((status = osmv_query_sa(bind_handle, &req)) != IB_SUCCESS) {
		fprintf(stderr, "Query SA failed: %s\n",
			ib_get_err_str(status));
		return (status);
	}

	if (result.status != IB_SUCCESS) {
		fprintf(stderr, "Query result returned: %s\n",
			ib_get_err_str(result.status));
		return (result.status);
	}
	return (status);
}

/*
 * Get the portinfo records available with IsSM or IsSMdisabled CapabilityMask bit on.
 */
static ib_api_status_t
get_issm_records(osm_bind_handle_t bind_handle, ib_net32_t capability_mask)
{
	ib_api_status_t   status;
	osmv_query_req_t  req;
	osmv_user_query_t user;
	ib_portinfo_record_t attr;

	memset( &req, 0, sizeof( req ) );
	memset( &user, 0, sizeof( user ) );
	memset( &attr, 0, sizeof ( attr ) );
	attr.port_info.capability_mask = capability_mask;

	user.attr_id = IB_MAD_ATTR_PORTINFO_RECORD;
	user.attr_offset = ib_get_attr_offset(sizeof(ib_portinfo_record_t));
	user.attr_mod = cl_ntoh32(1 << 31);	/* enhanced query */
	user.comp_mask = IB_PIR_COMPMASK_CAPMASK;
	user.p_attr = &attr;

	req.query_type = OSMV_QUERY_USER_DEFINED;
	req.timeout_ms = sa_timeout_ms;
	req.retry_cnt = 1;
	req.flags = OSM_SA_FLAGS_SYNC;
	req.query_context = NULL;
	req.pfn_query_cb = query_res_cb;
	req.p_query_input = &user;
	req.sm_key = 0;

	if ((status = osmv_query_sa(bind_handle, &req)) != IB_SUCCESS) {
		fprintf(stderr, "Query SA failed: %s\n",
			ib_get_err_str(status));
		return (status);
	}

	if (result.status != IB_SUCCESS) {
		fprintf(stderr, "Query result returned: %s\n",
			ib_get_err_str(result.status));
		return (result.status);
	}
	return (status);
}

static ib_api_status_t
print_node_records(osm_bind_handle_t bind_handle)
{
	int               i = 0;
	ib_node_record_t *node_record = NULL;
	ib_net16_t        attr_offset = ib_get_attr_offset(sizeof(*node_record));
	ib_api_status_t   status;

	status  = get_all_records(bind_handle, IB_MAD_ATTR_NODE_RECORD, attr_offset, 0);
	if (status != IB_SUCCESS)
		return (status);

	if (node_print_desc == ALL_DESC) {
		printf("   LID \"name\"\n");
		printf("================\n");
	}
	for (i = 0; i < result.result_cnt; i++) {
		node_record = osmv_get_query_node_rec(result.p_result_madw, i);
		if (node_print_desc == ALL_DESC) {
			print_node_desc(node_record);
		} else if (node_print_desc == NAME_OF_LID) {
			if (requested_lid == cl_ntoh16(node_record->lid)) {
				print_node_record(node_record);
			}
		} else if (node_print_desc == NAME_OF_GUID) {
			ib_node_info_t *p_ni = &(node_record->node_info);

			if (requested_guid == cl_ntoh64(p_ni->port_guid)) {
				print_node_record(node_record);
			}
		} else {
			if (!requested_name ||
			    (strncmp(requested_name,
				     (char *)node_record->node_desc.description,
				     sizeof(node_record->node_desc.description)) == 0)) {
				print_node_record(node_record);
				if (node_print_desc == UNIQUE_LID_ONLY) {
					return_mad();
					exit(0);
				}
			}
		}
	}
	return_mad();
	return (status);
}

/**
 * return the lid from the node descriptor (name) supplied
 */
static ib_api_status_t
get_lid_from_name(osm_bind_handle_t bind_handle, const char *name, ib_net16_t *lid)
{
	int               i = 0;
	ib_node_record_t *node_record = NULL;
	ib_node_info_t   *p_ni = NULL;
	ib_net16_t        attr_offset = ib_get_attr_offset(sizeof(*node_record));
	ib_api_status_t   status;

	status = get_all_records(bind_handle, IB_MAD_ATTR_NODE_RECORD, attr_offset, 0);
	if (status != IB_SUCCESS)
		return (status);

	for (i = 0; i < result.result_cnt; i++) {
		node_record = osmv_get_query_node_rec(result.p_result_madw, i);
		p_ni = &(node_record->node_info);
		if (name && strncmp(name, (char *)node_record->node_desc.description,
				    sizeof(node_record->node_desc.description)) == 0) {
			*lid = cl_ntoh16(node_record->lid);
			break;
		}
	}
	return_mad();
	return (status);
}

static ib_api_status_t
get_print_path_rec_lid(osm_bind_handle_t bind_handle,
		       ib_net16_t src_lid,
		       ib_net16_t dst_lid)
{
	int                   i = 0;
	ib_path_rec_t         *path_record = NULL;
	osmv_query_req_t      req;
	osmv_lid_pair_t       lid_pair;
	ib_api_status_t       status;

	lid_pair.src_lid = cl_hton16(src_lid);
	lid_pair.dest_lid = cl_hton16(dst_lid);

	memset( &req, 0, sizeof( req ) );

	req.query_type = OSMV_QUERY_PATH_REC_BY_LIDS;
	req.timeout_ms = sa_timeout_ms;
	req.retry_cnt = 1;
	req.flags = OSM_SA_FLAGS_SYNC;
	req.query_context = NULL;
	req.pfn_query_cb = query_res_cb;
	req.p_query_input = (void *)&lid_pair;
	req.sm_key = 0;

	if ((status = osmv_query_sa(bind_handle, &req)) != IB_SUCCESS) {
		fprintf(stderr, "ERROR: Query SA failed: %s\n",
			ib_get_err_str(status));
		return (status);
	}
	if (result.status != IB_SUCCESS) {
		fprintf(stderr, "ERROR: Query result returned: %s\n",
			ib_get_err_str(result.status));
		return (result.status);
	}
	status = result.status;
	for (i = 0; i < result.result_cnt; i++) {
		path_record = osmv_get_query_path_rec(result.p_result_madw, i);
		print_path_record(path_record);
	}
	return_mad();
	return (status);
}

static ib_api_status_t
get_print_class_port_info(osm_bind_handle_t bind_handle)
{
	int                   i = 0;
	ib_class_port_info_t *class_port_info = NULL;
	osmv_query_req_t      req;
	ib_api_status_t       status;

	memset( &req, 0, sizeof( req ) );

	req.query_type = OSMV_QUERY_CLASS_PORT_INFO;
	req.timeout_ms = sa_timeout_ms;
	req.retry_cnt = 1;
	req.flags = OSM_SA_FLAGS_SYNC;
	req.query_context = NULL;
	req.pfn_query_cb = query_res_cb;
	req.p_query_input = NULL;
	req.sm_key = 0;

	if ((status = osmv_query_sa(bind_handle, &req)) != IB_SUCCESS) {
		fprintf(stderr, "ERROR: Query SA failed: %s\n",
			ib_get_err_str(status));
		return (status);
	}
	if (result.status != IB_SUCCESS) {
		fprintf(stderr, "ERROR: Query result returned: %s\n",
			ib_get_err_str(result.status));
		return (result.status);
	}
	status = result.status;
	for (i = 0; i < result.result_cnt; i++) {
		class_port_info = (ib_class_port_info_t*)osmv_get_query_result(result.p_result_madw, i);
		print_class_port_info(class_port_info);
	}
	return_mad();
	return (status);
}

static ib_api_status_t
print_path_records(osm_bind_handle_t bind_handle)
{
	int               i = 0;
	ib_path_rec_t    *path_record = NULL;
	ib_net16_t        attr_offset = ib_get_attr_offset(sizeof(*path_record));
	ib_api_status_t   status;

	status = get_all_records(bind_handle, IB_MAD_ATTR_PATH_RECORD, attr_offset, 0);
	if (status != IB_SUCCESS)
		return (status);

	for (i = 0; i < result.result_cnt; i++) {
		path_record = osmv_get_query_path_rec(result.p_result_madw, i);
		print_path_record(path_record);
	}
	return_mad();
	return (status);
}

static ib_api_status_t
print_portinfo_records(osm_bind_handle_t bind_handle)
{
	int                   i = 0;
	ib_portinfo_record_t *portinfo_record = NULL;
	ib_api_status_t       status;

	/* First, get IsSM records */
	status = get_issm_records(bind_handle, IB_PORT_CAP_IS_SM);
	if (status != IB_SUCCESS)
		return (status);

	printf("IsSM ports\n");
	for (i = 0; i < result.result_cnt; i++) {
		portinfo_record = osmv_get_query_portinfo_rec(result.p_result_madw, i);
		print_portinfo_record(portinfo_record);
	}
	return_mad();

	/* Now, get IsSMdisabled records */
	status = get_issm_records(bind_handle, IB_PORT_CAP_SM_DISAB);
	if (status != IB_SUCCESS)
		return (status);

	printf("\nIsSMdisabled ports\n");
	for (i = 0; i < result.result_cnt; i++) {
		portinfo_record = osmv_get_query_portinfo_rec(result.p_result_madw, i);
		print_portinfo_record(portinfo_record);
	}
	return_mad();

	return (status);
}

static ib_api_status_t
print_multicast_group_records(osm_bind_handle_t bind_handle, int members)
{
	int               i = 0;
	ib_member_rec_t  *mcast_record = NULL;
	ib_net16_t        mc_group_attr_offset = ib_get_attr_offset(sizeof(*mcast_record));
	osmv_query_res_t  mc_group_result;
	ib_net16_t        node_attr_offset = ib_get_attr_offset(sizeof(ib_node_record_t));
	ib_api_status_t   status;

	status = get_all_records(bind_handle, IB_MAD_ATTR_MCMEMBER_RECORD, mc_group_attr_offset, members);
	if (status != IB_SUCCESS)
		return (status);
	mc_group_result = result;

	status  = get_all_records(bind_handle, IB_MAD_ATTR_NODE_RECORD, node_attr_offset, 0);
	if (status != IB_SUCCESS)
		goto return_mc;

	for (i = 0; i < mc_group_result.result_cnt; i++) {
		mcast_record = osmv_get_query_mc_rec(mc_group_result.p_result_madw, i);
		if (members == 0)
			print_multicast_group_record(mcast_record);
		else
			print_multicast_member_record(mcast_record);
	}

	return_mad();

return_mc:
	/* return_mad for the mc_group_result */
	if (mc_group_result.p_result_madw != NULL) {
		osm_mad_pool_put(&mad_pool, mc_group_result.p_result_madw);
		mc_group_result.p_result_madw = NULL;
	}

	return (status);
}

static ib_api_status_t 
print_service_records(osm_bind_handle_t bind_handle)
{
	int                  i = 0;
	ib_service_record_t  *service_record = NULL;
	ib_net16_t           attr_offset = ib_get_attr_offset(sizeof(*service_record));
	ib_api_status_t      status;

	status = get_all_records(bind_handle, IB_MAD_ATTR_SERVICE_RECORD, attr_offset, 0);
	if (status != IB_SUCCESS)
		return (status);

	for (i = 0; i < result.result_cnt; i++) {
		service_record = osmv_get_query_svc_rec(result.p_result_madw, i);
		print_service_record(service_record);
	}
	return_mad();
	return (status);
}

static ib_api_status_t
print_inform_info_records(osm_bind_handle_t bind_handle)
{
	int                      i = 0;
	ib_inform_info_record_t  *inform_info_record = NULL;
	ib_net16_t               attr_offset = ib_get_attr_offset(sizeof(*inform_info_record));
	ib_api_status_t          status;

	status = get_all_records(bind_handle, IB_MAD_ATTR_INFORM_INFO_RECORD, attr_offset, 0);
	if (status != IB_SUCCESS)
		return (status); 

	for (i = 0; i < result.result_cnt; i++) {
		inform_info_record = osmv_get_query_inform_info_rec(result.p_result_madw, i);
		print_inform_info_record(inform_info_record);
	}
	return_mad();
	return (status);
}

static osm_bind_handle_t
get_bind_handle(void)
{
	uint32_t           i = 0;
	uint64_t           port_guid = (uint64_t)-1;
	osm_bind_handle_t  bind_handle;
	ib_api_status_t    status;
	ib_port_attr_t     attr_array[MAX_PORTS];
	uint32_t           num_ports = MAX_PORTS;

	complib_init();

	osm_log_construct(&log_osm);
	if ((status = osm_log_init_v2(&log_osm, TRUE, 0x0001, NULL,
				      0, TRUE)) != IB_SUCCESS) {
		fprintf(stderr, "Failed to init osm_log: %s\n",
			ib_get_err_str(status));
		exit(-1);
	}
	osm_log_set_level(&log_osm, OSM_LOG_NONE);
	if (osm_debug)
		osm_log_set_level(&log_osm, OSM_LOG_DEFAULT_LEVEL);

        vendor = osm_vendor_new(&log_osm, sa_timeout_ms);
	osm_mad_pool_construct(&mad_pool);
	if ((status = osm_mad_pool_init(&mad_pool, &log_osm)) != IB_SUCCESS) {
		fprintf(stderr, "Failed to init mad pool: %s\n",
			ib_get_err_str(status));
		exit(-1);
	}

	if ((status = osm_vendor_get_all_port_attr(vendor, attr_array, &num_ports)) != IB_SUCCESS) {
		fprintf(stderr, "Failed to get port attributes: %s\n",
			ib_get_err_str(status));
		exit(-1);
	}

	for (i = 0; i < num_ports; i++) {
		if (attr_array[i].link_state == IB_LINK_ACTIVE)
			port_guid = attr_array[i].port_guid;
	}

	if (port_guid == (uint64_t)-1) {
		fprintf(stderr, "Failed to find active port, check port status with \"ibstat\"\n");
		exit(-1);
	}

	bind_handle = osmv_bind_sa(vendor, &mad_pool, port_guid);

	if (bind_handle == OSM_BIND_INVALID_HANDLE) {
		fprintf(stderr, "Failed to bind to SA\n");
		exit(-1);
	}
	return (bind_handle);
}

static ib_net16_t
get_lid(osm_bind_handle_t bind_handle, const char * name)
{
	ib_net16_t rc_lid = 0;

	if (!name)
		return(0);
	if (isalpha(name[0]))
		assert(get_lid_from_name(bind_handle, name, &rc_lid) == IB_SUCCESS);
	else
		rc_lid = atoi(name);
	if (rc_lid == 0)
		fprintf(stderr, "Failed to find lid for \"%s\"\n", name);
        return (rc_lid);
}

static void
clean_up(void)
{
	osm_mad_pool_destroy(&mad_pool);
	osm_vendor_delete(&vendor);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [-h -d -P -N] [--list | -D] [-S -I -L -l -G -O -U -C -s -g -m --src-to-dst <src:dst> -t(imeout) <msec>] [<name> | <lid> | <guid>]\n", argv0);
	fprintf(stderr, "   Queries node records by default\n");
	fprintf(stderr, "   -d enable debugging\n");
	fprintf(stderr, "   -P get PathRecord info\n");
	fprintf(stderr, "   -N get NodeRecord info\n");
	fprintf(stderr, "   --list | -D the node desc of the CA's\n");
	fprintf(stderr, "   -S get ServiceRecord info\n");
	fprintf(stderr, "   -I get InformInfoRecord (subscription) info\n");
	fprintf(stderr, "   -L return the Lids of the name specified\n");
	fprintf(stderr, "   -l return the unique Lid of the name specified\n");
	fprintf(stderr, "   -G return the Guids of the name specified\n");
	fprintf(stderr, "   -O return name for the Lid specified\n");
	fprintf(stderr, "   -U return name for the Guid specified\n");
	fprintf(stderr, "   -C get the SA's class port info\n");
	fprintf(stderr, "   -s return the PortInfoRecords with isSM or isSMdisabled capability mask bit on\n");
	fprintf(stderr, "   -g get multicast group info\n");
	fprintf(stderr, "   -m get multicast member info\n");
	fprintf(stderr, "      (if multicast group specified, list member GIDs only for group specified\n");
	fprintf(stderr, "      specified, for example 'saquery -m 0xC000')\n");
	fprintf(stderr, "   --src-to-dst get a PathRecord for <src:dst>\n"
			"                where src amd dst are either node names or LIDs\n");
	fprintf(stderr, "   -t | --timeout <msec> specify the SA query response timeout (default %u msec)\n",
			DEFAULT_SA_TIMEOUT_MS);
	fprintf(stderr, "   --switch-map <switch-map> specify a switch map\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	int                ch = 0;
	int                members = 0;
	osm_bind_handle_t  bind_handle;
	char              *src = NULL;
	char              *dst = NULL;
	ib_net16_t         src_lid;
	ib_net16_t         dst_lid;
	ib_api_status_t    status;

	static char const str_opts[] = "PVNDLlGOUCSIsgmdht:";
	static const struct option long_opts [] = {
	   {"P", 0, 0, 'P'},
	   {"Version", 0, 0, 'V'},
	   {"N", 0, 0, 'N'},
	   {"L", 0, 0, 'L'},
	   {"l", 0, 0, 'l'},
	   {"G", 0, 0, 'G'},
	   {"O", 0, 0, 'O'},
	   {"U", 0, 0, 'U'},
	   {"s", 0, 0, 's'},
	   {"g", 0, 0, 'g'},
	   {"m", 0, 0, 'm'},
	   {"d", 0, 0, 'd'},
	   {"C", 0, 0, 'C'},
	   {"S", 0, 0, 'S'},
	   {"I", 0, 0, 'I'},
	   {"help", 0, 0, 'h'},
	   {"list", 0, 0, 'D'},
	   {"src-to-dst", 1, 0, 1},
	   {"timeout", 1, 0, 't'},
	   {"switch-map", 1, 0, 2},
	   { }
	};

	argv0 = argv[0];

	while ((ch = getopt_long(argc, argv, str_opts, long_opts, NULL)) != -1) {
		switch (ch) {
		case 1:
		{
			char *opt  = strdup(optarg);
			char *tok1 = strtok(opt, ":");
			char *tok2 = strtok(NULL, "\0");

			if (tok1 && tok2) {
				src = strdup(tok1);
				dst = strdup(tok2);
			} else {
				fprintf(stderr,
					"ERROR: --src-to-dst <node>:<node>\n");
				usage();
			}
			free(opt);
			query_type = IB_MAD_ATTR_PATH_RECORD;
			break;
		}
		case 2:
			switch_map = strdup(optarg);
			break;
		case 'P':
			query_type = IB_MAD_ATTR_PATH_RECORD;
			break;
		case 'V':
			fprintf(stderr, "%s %s\n", argv0, get_build_version() );
			exit(-1);
		case 'D':
			node_print_desc = ALL_DESC;
			break;
		case 'C':
			query_type = IB_MAD_ATTR_CLASS_PORT_INFO;
			break;
		case 'S':
			query_type = IB_MAD_ATTR_SERVICE_RECORD;
			break;
		case 'I':
			query_type = IB_MAD_ATTR_INFORM_INFO_RECORD;
			break;
		case 'N':
			query_type = IB_MAD_ATTR_NODE_RECORD;
			break;
		case 'L':
			node_print_desc = LID_ONLY;
			break;
		case 'l':
			node_print_desc = UNIQUE_LID_ONLY;
			break;
		case 'G':
			node_print_desc = GUID_ONLY;
			break;
		case 'O':
			node_print_desc = NAME_OF_LID;
			break;
		case 'U':
			node_print_desc = NAME_OF_GUID;
			break;
		case 's':
			query_type = IB_MAD_ATTR_PORTINFO_RECORD;
			break;
		case 'g':
			query_type = IB_MAD_ATTR_MCMEMBER_RECORD;
			break;
		case 'm':
			query_type = IB_MAD_ATTR_MCMEMBER_RECORD;
			members = 1;
			break;
		case 'd':
			osm_debug = 1;
			break;
		case 't':
			sa_timeout_ms = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc) {
		if (node_print_desc == NAME_OF_LID) {
			requested_lid = (ib_net16_t)strtoul(argv[0], NULL, 0);
			requested_lid_flag++;
		} else if (node_print_desc == NAME_OF_GUID) {
			requested_guid = (ib_net64_t)strtoul(argv[0], NULL, 0);;
			requested_guid_flag++;
		} else {
			requested_name = argv[0];
		}
	}

	if ((node_print_desc == LID_ONLY ||
	     node_print_desc == UNIQUE_LID_ONLY ||
	     node_print_desc == GUID_ONLY) &&
	     !requested_name) {
		fprintf(stderr, "ERROR: name not specified\n");
		usage();
	}

	if (node_print_desc == NAME_OF_LID && !requested_lid_flag) {
		fprintf(stderr, "ERROR: lid not specified\n");
		usage();
	} 

	if (node_print_desc == NAME_OF_GUID && !requested_guid_flag) {
		fprintf(stderr, "ERROR: guid not specified\n");
		usage();
	} 

	/* Note: lid cannot be 0; see infiniband spec 4.1.3 */
	if (node_print_desc == NAME_OF_LID && !requested_lid) {
		fprintf(stderr, "ERROR: lid invalid\n");
		usage();
	} 

	bind_handle = get_bind_handle();
	switch_map_fp = open_switch_map(switch_map);

	switch (query_type) {
	case IB_MAD_ATTR_NODE_RECORD:
		status = print_node_records(bind_handle);
		break;
	case IB_MAD_ATTR_PATH_RECORD:
		if (src && dst) {
        		src_lid = get_lid(bind_handle, src);
        		dst_lid = get_lid(bind_handle, dst);
			printf("Path record for %s -> %s\n", src, dst);
			if (src_lid == 0 || dst_lid == 0) {
	        		status = IB_UNKNOWN_ERROR;
			} else {
	        		status = get_print_path_rec_lid(bind_handle, src_lid, dst_lid);
			}
		} else {
			status = print_path_records(bind_handle);
		}
		break;
	case IB_MAD_ATTR_CLASS_PORT_INFO:
		status = get_print_class_port_info(bind_handle);
		break;
	case IB_MAD_ATTR_PORTINFO_RECORD:
		status = print_portinfo_records(bind_handle);
		break;
	case IB_MAD_ATTR_MCMEMBER_RECORD:
		status = print_multicast_group_records(bind_handle, members);
		break;
	case IB_MAD_ATTR_SERVICE_RECORD:
		status = print_service_records(bind_handle);
		break;
	case IB_MAD_ATTR_INFORM_INFO_RECORD:
		status = print_inform_info_records(bind_handle);
		break;
	default:
		fprintf(stderr, "Unknown query type %d\n", query_type);
		status = IB_UNKNOWN_ERROR;
		break;
	}

	if (src)
		free(src);
	if (dst)
		free(dst);
	clean_up();
	close_switch_map(switch_map_fp);
	return (status);
}
