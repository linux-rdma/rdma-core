/*
* SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
*
* NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
* property and proprietary rights in and to this material, related
* documentation and any modifications thereto. Any use, reproduction,
* disclosure or distribution of this material and related documentation
* without an express license agreement from NVIDIA CORPORATION or
* its affiliates is strictly prohibited.
*/


#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include <infiniband/mad.h>

#include "ext_umad.h"
#include "smi_gsi.h"

ports_record_t * ports_list_head = NULL;

ports_record_t * smi_gsi_record_find(int port_id)
{
	ports_record_t * x = ports_list_head;

	while (x) {
		if (x->smi_port_id == port_id)
			break;
		x = x->next;
	}

	return x;
}

ports_record_t * smi_gsi_record_add(int smi_port_id, int gsi_port_id)
{
	ports_record_t * x = (ports_record_t*) calloc(1, sizeof(ports_record_t));

	x->smi_port_id = smi_port_id;
	x->gsi_port_id = gsi_port_id;

	x->next = ports_list_head;
	ports_list_head = x;

	return x;
}

void smi_gsi_record_ptr_remove(ports_record_t * x)
{
	if (x) {
		if (x->prev)
			x->prev->next = x->next;
		else
			ports_list_head = x->next;

		if (x->next)
			x->next->prev = x->prev;

		free(x);
	}
}

void smi_gsi_record_remove(int id)
{
	smi_gsi_record_ptr_remove(smi_gsi_record_find(id));
}

int smi_gsi_port_by_class(int port_id, int mgmt)
{
	if (mgmt != IB_SMI_CLASS && mgmt != IB_SMI_DIRECT_CLASS) {
		ports_record_t * x = smi_gsi_record_find(port_id);

		if (!x) {
			IBWARN("Couldn't resolve SMI/GSI device for port_id %d.", port_id);
			return -1;
		}

		port_id = x->gsi_port_id;
	}

	return port_id;
}

int smi_gsi_port_open(char *ca_name, int portnum)
{
	ext_umad_ca_t ext_ca;
	int smi_port_id;
	int gsi_port_id;
	int rc;

	if ((rc = ext_umad_get_ca_by_name(ca_name, portnum, &ext_ca)) < 0) {
		IBWARN("Can't open UMAD port (%s) (%s:%d)", strerror(-rc), ca_name, portnum);
		return rc;
	}

	if ((smi_port_id = umad_open_port(ext_ca.smi.name, ext_ca.smi.preferred_port)) < 0) {
		IBWARN("Can't open SMI UMAD port (%s) (%s:%d)", strerror(-smi_port_id), ext_ca.smi.name, ext_ca.smi.preferred_port);
		return smi_port_id;
	}

	if ((gsi_port_id = umad_open_port(ext_ca.gsi.name, ext_ca.gsi.preferred_port)) < 0) {
		IBWARN("Can't open GSI UMAD port (%s) (%s:%d)", strerror(-gsi_port_id), ext_ca.gsi.name, ext_ca.gsi.preferred_port);
		umad_close_port(smi_port_id);
		return gsi_port_id;
	}

	if (smi_gsi_record_add(smi_port_id, gsi_port_id) < 0) {
		IBWARN("Failed to allocate memory for SMI/GSI mapping");
		umad_close_port(smi_port_id);
		umad_close_port(gsi_port_id);
		errno = ENOMEM;
		return -errno;
	}

	return smi_port_id;
}

void smi_gsi_port_close(int port_id)
{
	if (port_id > 0) {
		ports_record_t * x = smi_gsi_record_find(port_id);
		if (x) {
			umad_close_port(x->smi_port_id);
			umad_close_port(x->smi_port_id);
			smi_gsi_record_ptr_remove(x);
		}
		else {
			umad_close_port(port_id);
			IBWARN("Couldn't resolve SMI/GSI device for port_id %d.", port_id);
		}
	}
}
