/*
 * srp_daemon - discover SRP targets over IB
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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
 */

#ifndef SRP_DM_H
#define SRP_DM_H

#include <stdint.h>
#include <signal.h>
#include <endian.h>
#include <util/util.h>
#include <infiniband/verbs.h>
#include <infiniband/umad.h>
#include <linux/types.h>	/* __be16, __be32 and __be64 */
#include <ccan/build_assert.h>

#include "config.h"
#include "srp_ib_types.h"

#define SRP_CATAS_ERR SIGUSR1

enum {
	SRP_DM_ATTR_IO_UNIT_INFO    	  = 0x0010,
	SRP_DM_ATTR_IO_CONTROLLER_PROFILE = 0x0011,
	SRP_DM_ATTR_SERVICE_ENTRIES       = 0x0012
};

enum {
	SRP_DM_NO_IOC 	   = 0x0,
	SRP_DM_IOC_PRESENT = 0x1,
	SRP_DM_NO_SLOT 	   = 0xf
};

enum {
	SRP_SM_SUPPORTS_MASK_MATCH	= 1 << 13,
	SRP_IS_DM			= 1 << 19,
	SRP_SM_CAP_MASK_MATCH_ATTR_MOD	= 1 << 31,
};

enum {
	SRP_REV10_IB_IO_CLASS	= 0xff00,
	SRP_REV16A_IB_IO_CLASS	= 0x0100
};

struct srp_sa_node_rec {
	__be16		lid;
	__be16		reserved;
	uint8_t		base_version;
	uint8_t		class_version;
	uint8_t		type;
	uint8_t		num_ports;
	__be64		sys_guid __attribute__((packed));
	__be64		node_guid __attribute__((packed));
	__be64		port_guid __attribute__((packed));
	__be16		partition_cap;
	__be16		device_id;
	__be32		revision;
	__be32		port_num_vendor_id;
	uint8_t		desc[64];
};

struct srp_sa_port_info_rec {
	__be16		endport_lid;
	uint8_t		port_num;
	uint8_t		reserved;
	__be64		m_key __attribute__((packed));
	__be64		subnet_prefix __attribute__((packed));
	__be16		base_lid;
	__be16		master_sm_base_lid;
	__be32		capability_mask __attribute__((packed));
	__be16		diag_code;
	__be16		m_key_lease_period;
	uint8_t		local_port_num;
	uint8_t		link_width_enabled;
	uint8_t		link_width_supported;
	uint8_t		link_width_active;
	uint8_t		state_info1;
	uint8_t		state_info2;
	uint8_t		mkey_lmc;
	uint8_t		link_speed;
	uint8_t		mtu_smsl;
	uint8_t		vl_cap;
	uint8_t		vl_high_limit;
	uint8_t		vl_arb_high_cap;
	uint8_t		vl_arb_low_cap;
	uint8_t		mtu_cap;
	uint8_t		vl_stall_life;
	uint8_t		vl_enforce;
	__be16		m_key_violations;
	__be16		p_key_violations;
	__be16		q_key_violations;
	uint8_t		guid_cap;
	uint8_t		subnet_timeout;
	uint8_t		resp_time_value;
	uint8_t		error_threshold;
};

struct srp_dm_iou_info {
	__be16		change_id;
	uint8_t		max_controllers;
	uint8_t		diagid_optionrom;
	uint8_t		controller_list[128];
};

struct srp_dm_ioc_prof {
	__be64		guid;
	__be32		vendor_id;
	__be32		device_id;
	__be16		device_version;
	__be16		reserved1;
	__be32		subsys_vendor_id;
	__be32		subsys_device_id;
	__be16		io_class;
	__be16		io_subclass;
	__be16		protocol;
	__be16		protocol_version;
	__be32		reserved2;
	__be16		send_queue_depth;
	uint8_t		reserved3;
	uint8_t		rdma_read_depth;
	__be32		send_size;
	__be32		rdma_size;
	uint8_t		cap_mask;
	uint8_t		reserved4;
	uint8_t		service_entries;
	uint8_t		reserved5[9];
	char		id[64];
};

struct srp_dm_svc_entries {
	struct {
		char		name[40];
		__be64		id;
	}		service[4];
};

enum {
	SEND_SIZE  = 256,
	GRH_SIZE   = 40,
	RECV_BUF_SIZE   = SEND_SIZE + GRH_SIZE,
};

struct rule {
	int allow;
	char id_ext[17], ioc_guid[17], dgid[33], service_id[17], pkey[10], options[128];
};

#define  SRP_MAX_SHARED_PKEYS 127
#define  MAX_ID_EXT_STRING_LENGTH 17

struct target_details {
	uint16_t                pkey;
	char 			id_ext[MAX_ID_EXT_STRING_LENGTH];
	struct 			srp_dm_ioc_prof ioc_prof;
	uint64_t	 	subnet_prefix;
	uint64_t 		h_guid;
	uint64_t 		h_service_id;
	time_t 			retry_time;
	char			*options;
	struct target_details  *next;
};

struct config_t {
	char	       *dev_name;
	int		port_num;
	char	       *add_target_file;
	int		mad_retries;
	int		num_of_oust;
	int		cmd;
	int		once;
	int		execute;
	int		all;
	int		verbose;
	int		debug_verbose;
	int		timeout;
	int		recalc_time;
	int		print_initiator_ext;
	const char     *rules_file;
	struct rule    *rules;
	int 		retry_timeout;
	int		tl_retry_count;
};

extern struct config_t *config;

struct ud_resources {
	struct ibv_device	**dev_list;
	struct ibv_context      *ib_ctx;
	struct ibv_pd		*pd;
	struct ibv_cq           *send_cq;
	struct ibv_cq           *recv_cq;
	struct ibv_qp		*qp;
	struct ibv_mr           *mr;
	struct ibv_ah           *ah;
	char                    *recv_buf;
	char                    *send_buf;
	struct ibv_device_attr  device_attr;
	struct ibv_port_attr 	port_attr;
	int   	                cq_size;
	struct ibv_comp_channel *channel;
	pthread_mutex_t		*mad_buffer_mutex;
	struct umad_sa_packet	*mad_buffer;
};

struct umad_resources {
	struct ibv_context *ib_ctx;
	int		portid;
	int		agent;
	char	       *port_sysfs_path;
	uint16_t	sm_lid;
};

enum {
	SIZE_OF_TASKS_LIST = 5,
};

struct sync_resources {
	int stop_threads;
	int next_task;
	struct timespec next_recalc_time;
	struct {
		uint16_t lid;
		uint16_t pkey;
		union umad_gid gid;
	} tasks[SIZE_OF_TASKS_LIST];
	pthread_mutex_t mutex;
	struct target_details *retry_tasks_head;
	struct target_details *retry_tasks_tail;
	pthread_mutex_t retry_mutex;
	pthread_cond_t retry_cond;
};

struct resources {
	struct ud_resources   *ud_res;
	struct umad_resources *umad_res;
	struct sync_resources *sync_res;
	pthread_t trap_thread;
	pthread_t async_ev_thread;
	pthread_t reconnect_thread;
	pthread_t timer_thread;
};

struct srp_ib_user_mad {
	struct ib_user_mad hdr;
	char filler[MAD_BLOCK_SIZE];
};

#include <valgrind/drd.h>

#define pr_human(arg...)				\
	do {						\
		if (!config->cmd && !config->execute)	\
			printf(arg);			\
	} while (0)

void pr_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void pr_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

int pkey_index_to_pkey(struct umad_resources *umad_res, int pkey_index,
		       __be16 *pkey);
void handle_port(struct resources *res, uint16_t pkey, uint16_t lid, uint64_t h_guid);
void ud_resources_init(struct ud_resources *res);
int ud_resources_create(struct ud_resources *res);
int ud_resources_destroy(struct ud_resources *res);
int wait_for_recalc(struct resources *res_in);
int trap_main(struct resources *res);
void *run_thread_get_trap_notices(void *res_in);
void *run_thread_listen_to_events(void *res_in);
int get_node(struct umad_resources *umad_res, uint16_t dlid, uint64_t *guid);
int create_trap_resources(struct ud_resources *ud_res);
int register_to_traps(struct resources *res, int subscribe);
uint16_t get_port_lid(struct ibv_context *ib_ctx, int port_num,
		      uint16_t *sm_lid);
int create_ah(struct ud_resources *ud_res);
void push_gid_to_list(struct sync_resources *res, union umad_gid *gid,
		      uint16_t pkey);
void push_lid_to_list(struct sync_resources *res, uint16_t lid, uint16_t pkey);
struct target_details *pop_from_retry_list(struct sync_resources *res);
void push_to_retry_list(struct sync_resources *res,
			struct target_details *target);
int retry_list_is_empty(struct sync_resources *res);
void clear_traps_list(struct sync_resources *res);
int pop_from_list(struct sync_resources *res, uint16_t *lid,
		  union umad_gid *gid, uint16_t *pkey);
int sync_resources_init(struct sync_resources *res);
void sync_resources_cleanup(struct sync_resources *res);
int modify_qp_to_err(struct ibv_qp *qp);
void srp_sleep(time_t sec, time_t usec);
void wake_up_main_loop(char ch);
void __schedule_rescan(struct sync_resources *res, int when);
void schedule_rescan(struct sync_resources *res, int when);
int __rescan_scheduled(struct sync_resources *res);
int rescan_scheduled(struct sync_resources *res);

#endif /* SRP_DM_H */
