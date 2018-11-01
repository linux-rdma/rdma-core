/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
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

#include <infiniband/cmd_ioctl.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <infiniband/driver.h>
#include <infiniband/cmd_write.h>

static void scrub_esp_encap(struct ibv_flow_action_esp_encap *esp_encap)
{
	scrub_ptr_attr(esp_encap->val_ptr);
	scrub_ptr_attr(esp_encap->next_ptr);
}

static int copy_flow_action_esp(struct ibv_flow_action_esp_attr *esp,
				struct ibv_command_buffer *cmd)
{
	if (esp->comp_mask & IBV_FLOW_ACTION_ESP_MASK_ESN)
		fill_attr_in(cmd, UVERBS_ATTR_FLOW_ACTION_ESP_ESN,
			     &esp->esn, sizeof(esp->esn));

	if (esp->keymat_ptr)
		fill_attr_in_enum(cmd, UVERBS_ATTR_FLOW_ACTION_ESP_KEYMAT,
				  esp->keymat_proto,
				  esp->keymat_ptr, esp->keymat_len);
	if (esp->replay_ptr)
		fill_attr_in_enum(cmd, UVERBS_ATTR_FLOW_ACTION_ESP_REPLAY,
				  esp->replay_proto,
				  esp->replay_ptr, esp->replay_len);
	if (esp->esp_encap) {
		scrub_esp_encap(esp->esp_encap);
		fill_attr_in_ptr(cmd, UVERBS_ATTR_FLOW_ACTION_ESP_ENCAP,
				 esp->esp_encap);
	}
	if (esp->esp_attr)
		fill_attr_in_ptr(cmd, UVERBS_ATTR_FLOW_ACTION_ESP_ATTRS,
				 esp->esp_attr);

	return 0;
}

#define FLOW_ACTION_ESP_ATTRS_NUM	6
int ibv_cmd_create_flow_action_esp(struct ibv_context *ctx,
				   struct ibv_flow_action_esp_attr *attr,
				   struct verbs_flow_action *flow_action,
				   struct ibv_command_buffer *driver)
{
	DECLARE_COMMAND_BUFFER_LINK(cmd, UVERBS_OBJECT_FLOW_ACTION,
				     UVERBS_METHOD_FLOW_ACTION_ESP_CREATE,
				     FLOW_ACTION_ESP_ATTRS_NUM,
				     driver);
	struct ib_uverbs_attr *handle = fill_attr_out_obj(
		cmd, UVERBS_ATTR_CREATE_FLOW_ACTION_ESP_HANDLE);
	int ret;

	ret = copy_flow_action_esp(attr, cmd);
	if (ret)
		return ret;

	ret = execute_ioctl(ctx, cmd);
	if (ret)
		return errno;

	flow_action->action.context = ctx;
	flow_action->type = IBV_FLOW_ACTION_ESP;
	flow_action->handle = read_attr_obj(
		UVERBS_ATTR_CREATE_FLOW_ACTION_ESP_HANDLE, handle);

	return 0;
}

int ibv_cmd_modify_flow_action_esp(struct verbs_flow_action *flow_action,
				   struct ibv_flow_action_esp_attr *attr,
				   struct ibv_command_buffer *driver)
{
	DECLARE_COMMAND_BUFFER_LINK(cmd, UVERBS_OBJECT_FLOW_ACTION,
				     UVERBS_METHOD_FLOW_ACTION_ESP_MODIFY,
				     FLOW_ACTION_ESP_ATTRS_NUM, driver);
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_MODIFY_FLOW_ACTION_ESP_HANDLE,
			 flow_action->handle);

	ret = copy_flow_action_esp(attr, cmd);
	if (ret)
		return ret;

	return execute_ioctl(flow_action->action.context, cmd);
}

int ibv_cmd_destroy_flow_action(struct verbs_flow_action *action)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_FLOW_ACTION,
			       UVERBS_METHOD_FLOW_ACTION_DESTROY, 1);
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_DESTROY_FLOW_ACTION_HANDLE,
			 action->handle);
	ret = execute_ioctl(action->action.context, cmd);
	if (verbs_is_destroy_err(&ret))
		return ret;

	return 0;
}

