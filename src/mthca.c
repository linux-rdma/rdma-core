/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>

#include <infiniband/driver.h>

#include "mthca.h"

enum {
	TAVOR,
	ARBEL
};

static struct ibv_device_ops mthca_ops[] = {
	[TAVOR] = { },
	[ARBEL] = { }
};

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX		0x15b3
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_TAVOR
#define PCI_DEVICE_ID_MELLANOX_TAVOR	0x5a44
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT
#define PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT 0x6278
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_ARBEL
#define PCI_DEVICE_ID_MELLANOX_ARBEL	0x6282
#endif

#ifndef PCI_VENDOR_ID_TOPSPIN
#define PCI_VENDOR_ID_TOPSPIN		0x1867
#endif

#define HCA(v, d, t) \
	{ .vendor = PCI_VENDOR_ID_##v,			\
	  .device = PCI_DEVICE_ID_MELLANOX_##d,		\
	  .type = t }

struct {
	unsigned vendor;
	unsigned device;
	int      type;
} hca_table[] = {
	HCA(MELLANOX, TAVOR, TAVOR),
	HCA(MELLANOX, ARBEL_COMPAT, TAVOR),
	HCA(MELLANOX, ARBEL, ARBEL),
	HCA(TOPSPIN, TAVOR, TAVOR),
	HCA(TOPSPIN, ARBEL_COMPAT, TAVOR),
	HCA(TOPSPIN, ARBEL, ARBEL),
};

struct ibv_device *openib_driver_init(struct sysfs_class_device *sysdev)
{
	struct sysfs_device    *pcidev;
	struct sysfs_attribute *attr;
	struct mthca_device    *dev;
	unsigned                vendor, device;
	int                     i;

	pcidev = sysfs_get_classdev_device(sysdev);
	if (!pcidev)
		return NULL;

	attr = sysfs_get_device_attr(pcidev, "vendor");
	if (!attr)
		return NULL;
	sscanf(attr->value, "%i", &vendor);
	sysfs_close_attribute(attr);

	attr = sysfs_get_device_attr(pcidev, "device");
	if (!attr)
		return NULL;
	sscanf(attr->value, "%i", &device);
	sysfs_close_attribute(attr);

	for (i = 0; i < sizeof hca_table / sizeof hca_table[0]; ++i)
		if (vendor == hca_table[i].vendor &&
		    device == hca_table[i].device)
			goto found;

	return NULL;

found:
	dev = malloc(sizeof *dev);
	if (!dev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			sysdev->name);
		abort();
	}

	dev->ibv_dev.ops = mthca_ops[hca_table[i].type];

	return &dev->ibv_dev;
}
