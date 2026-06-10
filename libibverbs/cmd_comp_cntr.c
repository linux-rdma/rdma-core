// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <infiniband/cmd_write.h>

int ibv_cmd_create_comp_cntr(struct ibv_context *context,
			     struct ibv_comp_cntr *comp_cntr,
			     struct ibv_command_buffer *link)
{
	DECLARE_COMMAND_BUFFER_LINK(cmdb, UVERBS_OBJECT_COMP_CNTR,
				    UVERBS_METHOD_COMP_CNTR_CREATE, 3, link);
	struct ib_uverbs_attr *handle;
	int ret;

	comp_cntr->context = context;

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_CREATE_COMP_CNTR_HANDLE);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_COMP_CNTR_RESP_COUNT_MAX_VALUE,
			  &comp_cntr->comp_count_max_value);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_COMP_CNTR_RESP_ERR_COUNT_MAX_VALUE,
			  &comp_cntr->err_count_max_value);

	ret = execute_ioctl(context, cmdb);
	if (ret)
		return errno;

	comp_cntr->handle = read_attr_obj(UVERBS_ATTR_CREATE_COMP_CNTR_HANDLE, handle);
	return 0;
}

int ibv_cmd_destroy_comp_cntr(struct ibv_comp_cntr *comp_cntr)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_COMP_CNTR, UVERBS_METHOD_COMP_CNTR_DESTROY, 1);
	int ret;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_COMP_CNTR_HANDLE, comp_cntr->handle);

	ret = execute_ioctl(comp_cntr->context, cmdb);
	if (verbs_is_destroy_err(&ret))
		return ret;

	return 0;
}

static int ibv_icmd_modify_comp_cntr(struct ibv_comp_cntr *comp_cntr,
				     uint8_t entry, uint8_t op, uint64_t value)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_COMP_CNTR, UVERBS_METHOD_COMP_CNTR_MODIFY, 4);

	fill_attr_in_obj(cmdb, UVERBS_ATTR_MODIFY_COMP_CNTR_HANDLE, comp_cntr->handle);
	fill_attr_const_in(cmdb, UVERBS_ATTR_MODIFY_COMP_CNTR_ENTRY, entry);
	fill_attr_const_in(cmdb, UVERBS_ATTR_MODIFY_COMP_CNTR_OP, op);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_MODIFY_COMP_CNTR_VALUE, value);

	return execute_ioctl(comp_cntr->context, cmdb);
}

int ibv_cmd_set_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t value)
{
	return ibv_icmd_modify_comp_cntr(comp_cntr, IB_UVERBS_COMP_CNTR_ENTRY_COMP,
					 IB_UVERBS_COMP_CNTR_MODIFY_OP_SET, value);
}

int ibv_cmd_set_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t value)
{
	return ibv_icmd_modify_comp_cntr(comp_cntr, IB_UVERBS_COMP_CNTR_ENTRY_ERR,
					 IB_UVERBS_COMP_CNTR_MODIFY_OP_SET, value);
}

int ibv_cmd_inc_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t amount)
{
	return ibv_icmd_modify_comp_cntr(comp_cntr, IB_UVERBS_COMP_CNTR_ENTRY_COMP,
					 IB_UVERBS_COMP_CNTR_MODIFY_OP_INC, amount);
}

int ibv_cmd_inc_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t amount)
{
	return ibv_icmd_modify_comp_cntr(comp_cntr, IB_UVERBS_COMP_CNTR_ENTRY_ERR,
					 IB_UVERBS_COMP_CNTR_MODIFY_OP_INC, amount);
}

static int ibv_icmd_read_comp_cntr(struct ibv_comp_cntr *comp_cntr,
				   uint8_t entry, uint64_t *value)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_COMP_CNTR, UVERBS_METHOD_COMP_CNTR_READ, 3);

	fill_attr_in_obj(cmdb, UVERBS_ATTR_READ_COMP_CNTR_HANDLE, comp_cntr->handle);
	fill_attr_const_in(cmdb, UVERBS_ATTR_READ_COMP_CNTR_ENTRY, entry);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_READ_COMP_CNTR_RESP_VALUE, value);

	return execute_ioctl(comp_cntr->context, cmdb);
}

int ibv_cmd_read_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t *value)
{
	return ibv_icmd_read_comp_cntr(comp_cntr, IB_UVERBS_COMP_CNTR_ENTRY_COMP, value);
}

int ibv_cmd_read_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t *value)
{
	return ibv_icmd_read_comp_cntr(comp_cntr, IB_UVERBS_COMP_CNTR_ENTRY_ERR, value);
}

int ibv_cmd_qp_attach_comp_cntr(struct ibv_qp *qp, struct ibv_comp_cntr *comp_cntr,
				struct ibv_qp_attach_comp_cntr_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_QP, UVERBS_METHOD_QP_ATTACH_COMP_CNTR, 3);
	uint32_t op_mask = 0;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_QP_ATTACH_COMP_CNTR_HANDLE, qp->handle);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_QP_ATTACH_COMP_CNTR_CNTR_HANDLE, comp_cntr->handle);

	if (attr->op_mask & IBV_QP_ATTACH_COMP_CNTR_OP_SEND)
		op_mask |= IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_SEND;
	if (attr->op_mask & IBV_QP_ATTACH_COMP_CNTR_OP_RECV)
		op_mask |= IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_RECV;
	if (attr->op_mask & IBV_QP_ATTACH_COMP_CNTR_OP_RDMA_READ)
		op_mask |= IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_RDMA_READ;
	if (attr->op_mask & IBV_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_READ)
		op_mask |= IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_READ;
	if (attr->op_mask & IBV_QP_ATTACH_COMP_CNTR_OP_RDMA_WRITE)
		op_mask |= IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_RDMA_WRITE;
	if (attr->op_mask & IBV_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_WRITE)
		op_mask |= IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_WRITE;

	fill_attr_in_uint32(cmdb, UVERBS_ATTR_QP_ATTACH_COMP_CNTR_OP_MASK, op_mask);

	return execute_ioctl(qp->context, cmdb);
}
