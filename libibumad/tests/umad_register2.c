/*
 * Copyright (c) 2014 Intel Corporation, All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <infiniband/umad.h>

#define UNLIKELY_MGMT_CLASS 0x2F
#define UNLIKELY_RMPP_MGMT_CLASS 0x4F

struct ib_user_mad_reg_req2 {
	uint32_t id;
	uint32_t qpn;
	uint8_t  mgmt_class;
	uint8_t  mgmt_class_version;
	uint16_t res;
	uint32_t flags;
	uint64_t method_mask[2];
	uint32_t oui;
	uint8_t  rmpp_version;
	uint8_t  reserved[3];
};

static int test_failures = 0;

static void dump_reg_attr(struct umad_reg_attr *reg_attr)
{
	printf("\nmgmt_class %u\n"
		"mgmt_class_version %u\n"
		"flags 0x%08x\n"
		"method_mask 0x%016"PRIx64" %016"PRIx64"\n"
		"oui 0x%06x\n"
		"rmpp_version %u\n\n",
	      reg_attr->mgmt_class,
	      reg_attr->mgmt_class_version,
	      reg_attr->flags,
	      reg_attr->method_mask[1], reg_attr->method_mask[0],
	      reg_attr->oui,
	      reg_attr->rmpp_version);
}

static int open_test_device(void)
{
	int fd = umad_open_port(NULL, 0);
	if (fd < 0) {
		printf("\n *****\nOpen Port Failure...  Aborting\n");
		printf("       Ensure you have an HCA to test against.\n");
		exit(0);
	}
	return fd;
}

static void test_fail(void)
{
	int rc = 0;
	struct umad_reg_attr reg_attr;
	uint32_t agent_id;
	uint32_t agent_id2;
	int fd;

	printf("\n *****\nBegin invalid tests\n");

	fd = open_test_device();

	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_MGMT_CLASS;
	reg_attr.mgmt_class_version = 0x1;
	reg_attr.flags = 0x80000000;
	printf("\n invalid register flags ... ");
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc == 0) {
		printf("\n umad_register2 registered invalid flags. rc = %d\n",
			rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = 0x03;
	reg_attr.mgmt_class_version = 0x2;
	reg_attr.rmpp_version = 0x02;
	printf("\n invalid rmpp_version ... ");
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc == 0) {
		printf("\n umad_register2 registered an invalid rmpp_version. rc = %d\n",
			rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_RMPP_MGMT_CLASS;
	reg_attr.oui = 0x0100066a;
	printf("\n invalid oui ... ");
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc == 0) {
		printf("\n umad_register2 registered an invalid oui. rc = %d\n",
			rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	/* The following 2 registrations attempt to register the same OUI 2
	 * times.  The second one is supposed to fail with the same method
	 * mask.
	 */
	printf("\n duplicate oui ... ");
	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_RMPP_MGMT_CLASS;
	reg_attr.mgmt_class_version = 0x1;
	reg_attr.rmpp_version = 0x00;
	reg_attr.oui = 0x00066a;
	reg_attr.method_mask[0] = 0x80000000000000DEULL;
	reg_attr.method_mask[1] = 0xAD00000000000001ULL;
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc != 0) {
		printf("\n umad_register2 Failed to register an oui for the duplicate test. rc = %d\n",
			rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	}

	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_RMPP_MGMT_CLASS;
	reg_attr.mgmt_class_version = 0x1;
	reg_attr.rmpp_version = 0x00;
	reg_attr.oui = 0x00066a;
	reg_attr.method_mask[0] = 0x80000000000000DEULL;
	reg_attr.method_mask[1] = 0xAD00000000000001ULL;
	rc = umad_register2(fd, &reg_attr, &agent_id2);
	if (rc == 0) {
		printf("\n umad_register2 registered a duplicate oui. rc = %d\n",
			rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
		umad_unregister(fd, agent_id2);
	}

	umad_close_port(fd);
out:
	printf("\n *****\nEnd invalid tests\n");
}

static void test_oui(void)
{
	int rc = 0;
	struct umad_reg_attr reg_attr;
	uint32_t agent_id;
	int fd;

	printf("\n *****\nStart valid oui tests\n");

	fd = open_test_device();

	printf("\n valid oui ... ");
	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_RMPP_MGMT_CLASS;
	reg_attr.mgmt_class_version = 0x1;
	reg_attr.rmpp_version = 0x00;
	reg_attr.oui = 0x00066a;
	reg_attr.method_mask[0] = 0x80000000000000DEULL;
	reg_attr.method_mask[1] = 0xAD00000000000001ULL;
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc != 0) {
		printf("\n umad_register2 failed oui 0x%x. rc = %d\n",
			reg_attr.oui, rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	printf("\n valid oui with flags ... ");
	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_RMPP_MGMT_CLASS;
	reg_attr.mgmt_class_version = 0x1;
	reg_attr.rmpp_version = 0x00;
	reg_attr.flags = 0x01;
	/* Use Intel OUI for testing */
	reg_attr.oui = 0x00066a;
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc != 0) {
		printf("\n umad_register2 failed oui 0x%x with flags 0x%x. rc = %d\n",
			reg_attr.oui, reg_attr.flags, rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
		goto out;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	umad_close_port(fd);

out:
	printf("\n End valid oui tests\n *****\n");
}

static void check_register2_support(void)
{
	struct ib_user_mad_reg_req2 req;
	int fd;

	fd = open_test_device();

	memset(&req, 0, sizeof(req));
	req.mgmt_class = UNLIKELY_MGMT_CLASS;
	req.mgmt_class_version = 0x1;
	req.qpn = 0x1;

	if (ioctl(fd, IB_USER_MAD_REGISTER_AGENT2, (void *)&req) != 0) {
		if (errno == ENOTTY || errno == EINVAL) {
			printf("\n *****\nKernel does not support the new ioctl.  Aborting tests\n");
			exit(0);
		}
	}

	umad_close_port(fd);
}

int main(int argc, char *argv[])
{
	//umad_debug(1);
	check_register2_support();
	test_fail();
	test_oui();
	printf("\n *******************\n");
	printf("   umad_register2 had %d failures\n", test_failures);
	printf(" *******************\n");
	return test_failures;
}
