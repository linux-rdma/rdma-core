/*
 * Copyright (c) 2004,2005 Voltaire Inc.  All rights reserved.
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
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include <common.h>
#include <mad.h>

void
mad_dump_int(char *buf, int bufsz, void *val, int valsz)
{
	switch (valsz) {
	case 1:
		snprintf(buf, bufsz, "%d", *(uint8 *)val);
		break;
	case 2:
		snprintf(buf, bufsz, "%d", *(uint16 *)val);
		break;
	case 3:
	case 4:
		snprintf(buf, bufsz, "%d", *(uint32 *)val);
		break;
	case 5: case 6: case 7:
	case 8:
		snprintf(buf, bufsz, "%llu", *(uint64 *)val);
		break;
	default:
		WARN("bad int sz %d", valsz);
		buf[0] = 0;
	}
}

void
mad_dump_uint(char *buf, int bufsz, void *val, int valsz)
{
	switch (valsz) {
	case 1:
		snprintf(buf, bufsz, "%u", *(uint8 *)val);
		break;
	case 2:
		snprintf(buf, bufsz, "%u", *(uint16 *)val);
		break;
	case 3:
	case 4:
		snprintf(buf, bufsz, "%u", *(uint32 *)val);
		break;
	case 5:
	case 6:
	case 7:
	case 8:
		snprintf(buf, bufsz, "%llu", *(uint64 *)val);
		break;
	default:
		WARN("bad int sz %u", valsz);
		buf[0] = 0;
	}
}

void
mad_dump_hex(char *buf, int bufsz, void *val, int valsz)
{
	switch (valsz) {
	case 1:
		snprintf(buf, bufsz, "0x%x", *(uint8 *)val);
		break;
	case 2:
		snprintf(buf, bufsz, "0x%x", *(uint16 *)val);
		break;
	case 3:
		snprintf(buf, bufsz, "0x%x", *(uint32 *)val & 0xffffff);
		break;
	case 4:
		snprintf(buf, bufsz, "0x%x", *(uint32 *)val);
		break;
	case 5:
		snprintf(buf, bufsz, "0x%llx", *(uint64 *)val & 0xffffffffffllu);
		break;
	case 6:
		snprintf(buf, bufsz, "0x%llx", *(uint64 *)val & 0xffffffffffffllu);
		break;
	case 7:
		snprintf(buf, bufsz, "0x%llx", *(uint64 *)val & 0xffffffffffffffllu);
		break;
	case 8:
		snprintf(buf, bufsz, "0x%llx", *(uint64 *)val);
		break;
	default:
		WARN("bad int sz %d", valsz);
		buf[0] = 0;
	}
}

void
mad_dump_linkwidth(char *buf, int bufsz, void *val, int valsz)
{
	int width = *(int *)val;

	switch (width) {
	case 1:
		snprintf(buf, bufsz, "1X");
		break;
	case 2:
		snprintf(buf, bufsz, "4X");
		break;
	case 8:
		snprintf(buf, bufsz, "12X");
		break;
	default:
		WARN("bad width %d", width);
		buf[0] = 0;
	}
}

void
mad_dump_linkwidthsup(char *buf, int bufsz, void *val, int valsz)
{
	int width = *(int *)val;

	switch (width) {
	case 1:
		snprintf(buf, bufsz, "1X");
		break;
	case 3:
		snprintf(buf, bufsz, "1X or 4X");
		break;
	case 11:
		snprintf(buf, bufsz, "1X, 4X or 12X");
		break;
	default:
		WARN("bad width %d", width);
		buf[0] = 0;
	}
}

void
mad_dump_linkwidthen(char *buf, int bufsz, void *val, int valsz)
{
	int width = *(int *)val;
	char *s = buf, *e = s + bufsz;

	if (width & 0x1)
		s += snprintf(s, e - s, "1X or ");
	if (s < e && (width & 0x2))
		s += snprintf(s, e - s, "4X or ");
	if (s < e && (width & 0x4))
		s += snprintf(s, e - s, "8X or ");
	if (s < e && (width & 0x8))
		s += snprintf(s, e - s, "12X or ");

	if ((width >> 4) || s == buf)
		s += snprintf(s, e - s, "?(%d)", width);
	else
		s[-3] = 0;
}

void
mad_dump_linkspeed(char *buf, int bufsz, void *val, int valsz)
{
	int speed = *(int *)val;

	switch (speed) {
	case 1:
		snprintf(buf, bufsz, "2.5 Gbs");
		break;
	case 15:
		snprintf(buf, bufsz, "SpeedSupported");
		break;
	default:
		snprintf(buf, bufsz, "?(%d)", speed);
	}
}

void
mad_dump_portstate(char *buf, int bufsz, void *val, int valsz)
{
	int state = *(int *)val;

	switch (state) {
	case 0:
		snprintf(buf, bufsz, "NoChange");
		break;
	case 1:
		snprintf(buf, bufsz, "Down");
		break;
	case 2:
		snprintf(buf, bufsz, "Initialize");
		break;
	case 3:
		snprintf(buf, bufsz, "Armed");
		break;
	case 4:
		snprintf(buf, bufsz, "Active");
		break;
	default:
		snprintf(buf, bufsz, "?(%d)", state);
	}
}

void
mad_dump_physportstate(char *buf, int bufsz, void *val, int valsz)
{
	int state = *(int *)val;

	switch (state) {
	case 0:
		snprintf(buf, bufsz, "NoChange");
		break;
	case 1:
		snprintf(buf, bufsz, "Sleep");
		break;
	case 2:
		snprintf(buf, bufsz, "Polling");
		break;
	case 3:
		snprintf(buf, bufsz, "Disabled");
		break;
	case 4:
		snprintf(buf, bufsz, "PortConfigurationTraining");
		break;
	case 5:
		snprintf(buf, bufsz, "LinkUp");
		break;
	case 6:
		snprintf(buf, bufsz, "LinkErrorRecovery");
		break;
	default:
		snprintf(buf, bufsz, "?(%d)", state);
	}
}

void
mad_dump_mtu(char *buf, int bufsz, void *val, int valsz)
{
	int mtu = *(int *)val;

	switch (mtu) {
	case 1:
		snprintf(buf, bufsz, "256");
		break;
	case 2:
		snprintf(buf, bufsz, "512");
		break;
	case 3:
		snprintf(buf, bufsz, "1024");
		break;
	case 4:
		snprintf(buf, bufsz, "2048");
		break;
	case 5:
		snprintf(buf, bufsz, "4096");
		break;
	default:
		snprintf(buf, bufsz, "?(%d)", mtu);
		buf[0] = 0;
	}
}

void
mad_dump_vlcap(char *buf, int bufsz, void *val, int valsz)
{
	int vlcap = *(int *)val;

	switch (vlcap) {
	case 1:
		snprintf(buf, bufsz, "VL0");
		break;
	case 2:
		snprintf(buf, bufsz, "VL0-1");
		break;
	case 3:
		snprintf(buf, bufsz, "VL0-3");
		break;
	case 4:
		snprintf(buf, bufsz, "VL0-7");
		break;
	case 5:
		snprintf(buf, bufsz, "VL0-14");
		break;
	default:
		snprintf(buf, bufsz, "?(%d)", vlcap);
	}
}

void
mad_dump_portcapmask(char *buf, int bufsz, void *val, int valsz)
{
	uint mask = *(uint *)val;
	char *s = buf;

	s += sprintf(s, "(0x%x):\n", mask);
	if (mask & (1 << 1))
		s += sprintf(s, "\t\t\t\tIsSM\n");
	if (mask & (1 << 2))
		s += sprintf(s, "\t\t\t\tIsNoticeSupported\n");
	if (mask & (1 << 3))
		s += sprintf(s, "\t\t\t\tIsTrapSupported\n");
	if (mask & (1 << 5))
		s += sprintf(s, "\t\t\t\tIsAutomaticMigrationSupported\n");
	if (mask & (1 << 6))
		s += sprintf(s, "\t\t\t\tIsSLMappingSupported\n");
	if (mask & (1 << 7))
		s += sprintf(s, "\t\t\t\tIsMKeyNVRAM\n");
	if (mask & (1 << 8))
		s += sprintf(s, "\t\t\t\tIsPKeyNVRAM\n");
	if (mask & (1 << 9))
		s += sprintf(s, "\t\t\t\tIsLedInfoSupported\n");
	if (mask & (1 << 10))
		s += sprintf(s, "\t\t\t\tIsSMdisabled\n");
	if (mask & (1 << 11))
		s += sprintf(s, "\t\t\t\tIsSystemImageGUIDsupported\n");
	if (mask & (1 << 12))
		s += sprintf(s, "\t\t\t\tIsPkeySwitchExternalPortTrapSupported\n");
	if (mask & (1 << 16))
		s += sprintf(s, "\t\t\t\tIsCommunicatonManagementSupported\n");
	if (mask & (1 << 17))
		s += sprintf(s, "\t\t\t\tIsSNMPTunnelingSupported\n");
	if (mask & (1 << 18))
		s += sprintf(s, "\t\t\t\tIsReinitSupported\n");
	if (mask & (1 << 19))
		s += sprintf(s, "\t\t\t\tIsDeviceManagementSupported\n");
	if (mask & (1 << 20))
		s += sprintf(s, "\t\t\t\tIsVendorClassSupported\n");
	if (mask & (1 << 21))
		s += sprintf(s, "\t\t\t\tIsDRNoticeSupported\n");
	if (mask & (1 << 22))
		s += sprintf(s, "\t\t\t\tIsCapabilityMaskNoticeSupported\n");
	if (mask & (1 << 23))
		s += snprintf(buf, bufsz, "\t\t\t\tIsBootManagementSupported\n");
	if (s != buf)
		*(--s) = 0;
}

void
mad_dump_bitfield(char *buf, int bufsz, void *val, int valsz)
{
	snprintf(buf, bufsz, "0x%x", *(uint32 *)val);
}

void
mad_dump_array(char *buf, int bufsz, void *val, int valsz)
{
	uint8 *p = val, *e;
	char *s = buf;

	if (bufsz < valsz*2)
		valsz = bufsz/2;

	for (p = val, e = p + valsz; p < e; p++, s += 2)
		sprintf(s, "%02x", *p);
}

void
mad_dump_string(char *buf, int bufsz, void *val, int valsz)
{
	if (bufsz < valsz)
		valsz = bufsz;

	snprintf(buf, valsz, "'%s'", (char *)val);
}

void
mad_dump_node_type(char *buf, int bufsz, void *val, int valsz)
{
	int nodetype = *(int*)val;

	switch (nodetype) {
 	case 1:
		snprintf(buf, bufsz, "Channel Adapter");
		break;
 	case 2:
		snprintf(buf, bufsz, "Switch");
		break;
 	case 3:
		snprintf(buf, bufsz, "Router");
		break;
	default:
		snprintf(buf, bufsz, "?(%d)?", nodetype);
		break;
	}
}

#define IB_MAX_NUM_VLS 16
#define IB_MAX_NUM_VLS_TO_U8 ((IB_MAX_NUM_VLS)/2)

typedef struct _ib_slvl_table {
	uint8_t vl_by_sl_num[IB_MAX_NUM_VLS_TO_U8];
} ib_slvl_table_t;

static inline void
ib_slvl_get_i(ib_slvl_table_t *tbl, int i, uint8_t *vl)
{
	*vl = (tbl->vl_by_sl_num[i >> 1] >> ((!(i&1)) << 2)) & 0xf;
}

typedef struct _ib_vl_arb_element {
	uint8_t res_vl; 
	uint8_t weight;
} __attribute__((packed)) ib_vl_arb_element_t;

#define IB_NUM_VL_ARB_ELEMENTS_IN_BLOCK 32
#define IB_NUM_VL_ARB_ELEMENTS_CONF_SUPPORT 8
#define IB_NUM_VL_ARB_BLOCKS_IN_TBL		2

typedef struct _ib_vl_arb_table {
  ib_vl_arb_element_t vl_entry[IB_NUM_VL_ARB_ELEMENTS_IN_BLOCK];
} ib_vl_arb_table_t;

typedef struct _ib_vl_arb_table_two_blocks {
  ib_vl_arb_table_t tbl_blocks[IB_NUM_VL_ARB_BLOCKS_IN_TBL];
} ib_vl_arb_table_two_blocks_t;

static inline uint8_t
ib_vl_arb_get_vl_entries_num_in_table(ib_vl_arb_table_t	*tbl)
{
	uint8_t i;

	for (i = 0; i<32; i++) {
		if (!(tbl->vl_entry[i].res_vl || tbl->vl_entry[i].weight))
			break;
	}

	return i;
}

static inline void
ib_vl_arb_get_vl(uint8_t res_vl, uint8_t *const vl )
{
	*vl = res_vl & 0x0F;
}

void
mad_dump_sltovl(char *buf, int bufsz, void *val, int valsz)
{
	ib_slvl_table_t* p_slvl_tbl = val;
	char buf_line1[1024];
	char buf_line2[1024];
	uint8_t vl;
	int i;

	buf_line1[0] = 0;
	buf_line2[0] = 0;

	for (i = 0; i < 16; i++)
		sprintf(buf_line1, "%s%-4u|", buf_line1, i);

	for (i = 0; i < 16; i++) {
		ib_slvl_get_i(p_slvl_tbl, i, &vl);
		sprintf(buf_line2, "%s0x%-2X|", buf_line2, vl);

	}
	
	snprintf(buf, bufsz, "\nSL: |%s\nVL: |%s\n", buf_line1, buf_line2);
}

void
mad_dump_vlarbitration(char *buf, int bufsz, void *val, int valsz)
{
	ib_vl_arb_table_t* p_vla_tbl = val;
	char buf_line1[1024];
	char buf_line2[1024];
	uint8_t vl;
	int i;

	buf_line1[0] = 0;
	buf_line2[0] = 0;

	for (i = 0; i<8; i++) {
		ib_vl_arb_get_vl(p_vla_tbl->vl_entry[i].res_vl, &vl);
		sprintf(buf_line1, "%s0x%-2X|", buf_line1, vl);
	}

	for (i = 0; i<8; i++)
		sprintf(buf_line2, "%s0x%-2X|",
			buf_line2, p_vla_tbl->vl_entry[i].weight);

	snprintf(buf, bufsz, "\nVL    : |%s\nWEIGHT: |%s\n", buf_line1, buf_line2);
}

static int
_dump_fields(char *buf, int bufsz, void *data, int start, int end)
{
	char val[64];
	char *s = buf;
	int n, field;

	for (field = start; field < end && bufsz > 0; field++) {
		mad_decode_field(data, field, val);
		if (!mad_dump_field(field, s, bufsz, val))
			return -1;
		n = strlen(s);
		s += n;
		*s++ = '\n';
		*s = 0;
		n++;
		bufsz -= n;
	}

	return s - buf;
}

void
mad_dump_nodedesc(char *buf, int bufsz, void *val, int valsz)
{
	strncpy(buf, val, bufsz);

	if (valsz < bufsz)
		buf[valsz] = 0;
}

void
mad_dump_nodeinfo(char *buf, int bufsz, void *val, int valsz)
{
	_dump_fields(buf, bufsz, val, IB_NODE_FIRST_F, IB_NODE_LAST_F);
}

void
mad_dump_portinfo(char *buf, int bufsz, void *val, int valsz)
{
	_dump_fields(buf, bufsz, val, IB_PORT_FIRST_F, IB_PORT_LAST_F);
}

void
mad_dump_switchinfo(char *buf, int bufsz, void *val, int valsz)
{
	_dump_fields(buf, bufsz, val, IB_SW_FIRST_F, IB_SW_LAST_F);
}
/************************/

char *
_mad_dump_val(ib_field_t *f, char *buf, int bufsz, void *val)
{
	f->def_dump_fn(buf, bufsz, val, ALIGN(f->bitlen, 8) / 8);
	buf[bufsz - 1] = 0;

	return buf;
}

char *
_mad_dump_field(ib_field_t *f, char *name, char *buf, int bufsz, void *val)
{
	char dots[128];
	int l, n;

	if (bufsz <= 32)
		return 0;		/* buf too small */

	if (!name)
		name = f->name;

	l = strlen(name);
	if (l < 32) {
		memset(dots, '.', 32 - l);
		dots[32 - l] = 0;
	}

	n = snprintf(buf, bufsz, "%s:%s", name, dots); 
	_mad_dump_val(f, buf + n, bufsz - n, val);
	buf[bufsz - 1] = 0;

	return buf;
}

int
_mad_dump(ib_mad_dump_fn *fn, char *name, void *val, int valsz)
{
	ib_field_t f = { .def_dump_fn = fn, .bitlen = valsz * 8}; 
	char buf[512];

	return printf("%s\n", _mad_dump_field(&f, name, buf, sizeof buf, val)); 
}

int 
_mad_print_field(ib_field_t *f, char *name, void *val, int valsz)
{
	return _mad_dump(f->def_dump_fn, name ? name : f->name, val, valsz ? valsz : ALIGN(f->bitlen, 8) / 8);
}
