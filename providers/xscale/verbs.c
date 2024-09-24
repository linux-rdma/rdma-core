// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ccan/array_size.h>

#include <util/compiler.h>
#include <util/mmio.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <infiniband/cmd_write.h>

#include "xscale.h"
#include "xsc-abi.h"

int xsc_query_port(struct ibv_context *context, u8 port,
		   struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

static void xsc_set_fw_version(struct ibv_device_attr *attr,
			       union xsc_ib_fw_ver *fw_ver)
{
	u8 ver_major = fw_ver->s.ver_major;
	u8 ver_minor = fw_ver->s.ver_minor;
	u16 ver_patch = fw_ver->s.ver_patch;
	u32 ver_tweak = fw_ver->s.ver_tweak;

	if (ver_tweak == 0) {
		snprintf(attr->fw_ver, sizeof(attr->fw_ver), "v%u.%u.%u",
			 ver_major, ver_minor, ver_patch);
	} else {
		snprintf(attr->fw_ver, sizeof(attr->fw_ver), "v%u.%u.%u+%u",
			 ver_major, ver_minor, ver_patch, ver_tweak);
	}
}

int xsc_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	union xsc_ib_fw_ver raw_fw_ver;
	int err;

	raw_fw_ver.data = 0;
	err = ibv_cmd_query_device_any(context, input, attr, attr_size,
				       &resp, &resp_size);
	if (err)
		return err;

	raw_fw_ver.data = resp.base.fw_ver;
	xsc_set_fw_version(&attr->orig_attr, &raw_fw_ver);

	return 0;
}
