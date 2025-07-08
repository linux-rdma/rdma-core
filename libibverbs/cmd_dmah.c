// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <infiniband/cmd_write.h>

int ibv_cmd_alloc_dmah(struct ibv_context *ctx,
		       struct verbs_dmah *dmah,
		       struct ibv_dmah_init_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DMAH, UVERBS_METHOD_DMAH_ALLOC, 4);
	struct ib_uverbs_attr *handle;
	int ret;

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_ALLOC_DMAH_HANDLE);
	if (attr->comp_mask & IBV_DMAH_INIT_ATTR_MASK_CPU_ID)
		fill_attr_in_uint32(cmdb, UVERBS_ATTR_ALLOC_DMAH_CPU_ID,
				    attr->cpu_id);
	if (attr->comp_mask & IBV_DMAH_INIT_ATTR_MASK_TPH_MEM_TYPE)
		fill_attr_in_enum(cmdb, UVERBS_ATTR_ALLOC_DMAH_TPH_MEM_TYPE,
				  attr->tph_mem_type, NULL, 0);
	if (attr->comp_mask & IBV_DMAH_INIT_ATTR_MASK_PH)
		fill_attr_in(cmdb, UVERBS_ATTR_ALLOC_DMAH_PH,
			     &attr->ph, sizeof(attr->ph));
	ret = execute_ioctl(ctx, cmdb);
	if (ret)
		return errno;

	dmah->handle = read_attr_obj(UVERBS_ATTR_ALLOC_DMAH_HANDLE, handle);
	dmah->dmah.context = ctx;

	return 0;
}

int ibv_cmd_free_dmah(struct verbs_dmah *dmah)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DMAH, UVERBS_METHOD_DMAH_FREE, 1);
	int ret;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_FREE_DMA_HANDLE, dmah->handle);

	ret = execute_ioctl(dmah->dmah.context, cmdb);
	if (verbs_is_destroy_err(&ret))
		return ret;

	return 0;
}
