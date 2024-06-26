/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_IB_USER_IOCTL_CMDS_H
#define HBL_IB_USER_IOCTL_CMDS_H

#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>

enum hbl_ib_objects {
	HBL_IB_OBJECT_USR_FIFO = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_OBJECT_SET_PORT_EX,
	HBL_IB_OBJECT_QUERY_PORT,
	HBL_IB_OBJECT_RESERVED,
	HBL_IB_OBJECT_ENCAP,
};

enum hbl_ib_usr_fifo_obj_methods {
	HBL_IB_METHOD_USR_FIFO_OBJ_CREATE = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_METHOD_USR_FIFO_OBJ_DESTROY,
};

enum hbl_ib_usr_fifo_create_attrs {
	HBL_IB_ATTR_USR_FIFO_CREATE_IN = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_ATTR_USR_FIFO_CREATE_OUT,
	HBL_IB_ATTR_USR_FIFO_CREATE_HANDLE,
};

enum hbl_ib_usr_fifo_destroy_attrs {
	HBL_IB_ATTR_USR_FIFO_DESTROY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum hbl_ib_device_methods {
	HBL_IB_METHOD_SET_PORT_EX = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_METHOD_QUERY_PORT,
};

enum hbl_ib_set_port_ex_attrs {
	HBL_IB_ATTR_SET_PORT_EX_IN = (1U << UVERBS_ID_NS_SHIFT),
};

enum hbl_ib_query_port_attrs {
	HBL_IB_ATTR_QUERY_PORT_IN = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_ATTR_QUERY_PORT_OUT,
};

enum hbl_ib_encap_methods {
	HBL_IB_METHOD_ENCAP_CREATE = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_METHOD_ENCAP_DESTROY,
};

enum hbl_ib_encap_create_attrs {
	HBL_IB_ATTR_ENCAP_CREATE_IN = (1U << UVERBS_ID_NS_SHIFT),
	HBL_IB_ATTR_ENCAP_CREATE_OUT,
	HBL_IB_ATTR_ENCAP_CREATE_HANDLE,
};

enum hbl_ib_encap_destroy_attrs {
	HBL_IB_ATTR_ENCAP_DESTROY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

#endif /* HBL_IB_USER_IOCTL_CMDS_H */
