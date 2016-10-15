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

#include <infiniband/umad.h>

#define UNLIKELY_MGMT_CLASS 0x2F
#define UNLIKELY_RMPP_MGMT_CLASS 0x4F

static int test_failures = 0;

/** =========================================================================
 * Stolen from OpenSM's register
 */
static int set_bit(int nr, void *method_mask)
{
	long mask, *addr = method_mask;
	int retval;

	addr += nr / (8 * sizeof(long));
	mask = 1L << (nr % (8 * sizeof(long)));
	retval = (mask & *addr) != 0;
	*addr |= mask;
	return retval;
}

static void set_bit64(int b, uint64_t *buf)
{
	uint64_t mask;
	uint64_t *addr = buf;

	addr += b >> 6;
	mask = 1ULL << (b & 0x3f);
	*addr |= mask;
}

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

static void test_register(void)
{
	int agent_id;
	long method_mask[16 / sizeof(long)];
	uint32_t class_oui = 0x001405; /* OPENIB_OUI */
	uint8_t oui[3];
	int fd;

	printf("\n old register test ... ");

	fd = open_test_device();

	memset(&method_mask, 0, sizeof(method_mask));
	set_bit( 1, &method_mask);
	set_bit(63, &method_mask);
	set_bit(64, &method_mask);

	// equal to this with the new register
	//reg_attr.method_mask[0] = 0x8000000000000002ULL;
	//reg_attr.method_mask[1] = 0x0000000000000001ULL;

	agent_id  = umad_register(fd, UNLIKELY_MGMT_CLASS, 0x1, 0x00, method_mask);
	if (agent_id < 0) {
		printf("\n umad_register Failure, agent_id %d\n", agent_id);
		printf("\n umad_register(fd, 0x01, 0x1, 0x00, method_mask);\n");
		test_failures++;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	printf("\n old register_oui test ... ");

	oui[0] = (class_oui >> 16) & 0xff;
	oui[1] = (class_oui >> 8) & 0xff;
	oui[2] = class_oui & 0xff;

	agent_id  = umad_register_oui(fd, UNLIKELY_RMPP_MGMT_CLASS, 0x1, oui, method_mask);
	if (agent_id < 0) {
		printf("\n umad_register_oui Failure, agent_id %d\n", agent_id);
		printf("\n umad_register(fd, 0x30, 0x1, oui, method_mask);\n");
		test_failures++;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	umad_close_port(fd);
}


static void test_fall_back(void)
{
	int rc = 0;
	struct umad_reg_attr reg_attr;
	uint32_t agent_id;
	int fd;

	fd = open_test_device();

	memset(&reg_attr, 0, sizeof(reg_attr));
	reg_attr.mgmt_class = UNLIKELY_MGMT_CLASS;
	reg_attr.mgmt_class_version = 0x1;
	reg_attr.oui = 0x001405; /* OPENIB_OUI */

	//reg_attr.method_mask[0] = 0x8000000000000002ULL;
	//reg_attr.method_mask[1] = 0x0000000000000001ULL;

	set_bit64( 1, (uint64_t *)&reg_attr.method_mask);
	set_bit64(63, (uint64_t *)&reg_attr.method_mask);
	set_bit64(64, (uint64_t *)&reg_attr.method_mask);

	printf("\n umad_register2 fall back (set_bit) ... ");
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc != 0) {
		printf("\n umad_register2 failed to fall back. rc = %d\n", rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	reg_attr.method_mask[0] = 0x8000000000000002ULL;
	reg_attr.method_mask[1] = 0x0000000000000001ULL;

	printf("\n umad_register2 fall back ... ");
	rc = umad_register2(fd, &reg_attr, &agent_id);
	if (rc != 0) {
		printf("\n umad_register2 failed to fall back. rc = %d\n", rc);
		dump_reg_attr(&reg_attr);
		test_failures++;
	} else {
		printf(" PASS\n");
		umad_unregister(fd, agent_id);
	}

	umad_close_port(fd);

}

int main(int argc, char *argv[])
{
	//umad_debug(1);

	printf("\n *****\nStart compatibility tests\n");

	test_register();
	test_fall_back();
	printf("\n *******************\n");
	printf("   umad_reg2_compat had %d failures\n", test_failures);
	printf(" *******************\n");
	return test_failures;
}
