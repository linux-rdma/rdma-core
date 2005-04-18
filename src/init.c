/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdio.h>
#include <dlfcn.h>

#include "ibverbs.h"

#ifndef OPENIB_DRIVER_PATH_ENV
#  define OPENIB_DRIVER_PATH_ENV "OPENIB_DRIVER_PATH"
#endif

Dlist *device_list;

static char default_path[] = DRIVER_PATH;

static Dlist *driver_list;

static void load_driver(char *so_path)
{
	void *dlhandle;
	ibv_driver_init_func init_func;
	struct ibv_driver *driver;

	dlhandle = dlopen(so_path, RTLD_NOW);
	if (!dlhandle)
		return;

	dlerror();
	init_func = dlsym(dlhandle, "openib_driver_init");
	if (dlerror() != NULL || !init_func) {
		dlclose(dlhandle);
		return;
	}

	driver = malloc(sizeof *driver);
	if (!driver) {
		fprintf(stderr, PFX "Fatal: couldn't allocate driver for %s\n", so_path);
		dlclose(dlhandle);
		return;
	}

	driver->init_func = init_func;
	dlist_push(driver_list, driver);
}

static void find_drivers(char *dir)
{
	size_t len = strlen(dir);
	glob_t so_glob;
	char *pat;
	int ret;
	int i;

	if (!len)
		return;

	while (len && dir[len - 1] == '/')
		dir[--len] = '\0';

	asprintf(&pat, "%s/*.so", dir);

	ret = glob(pat, 0, NULL, &so_glob);
	if (ret) {
		if (ret != GLOB_NOMATCH)
			fprintf(stderr, PFX "Warning: couldn't search %s\n", pat);
		return;
	}

	for (i = 0; i < so_glob.gl_pathc; ++i)
		load_driver(so_glob.gl_pathv[i]);
}

static void init_drivers(struct sysfs_class_device *verbs_dev)
{
	struct sysfs_class_device *ib_dev; 
	struct sysfs_attribute *attr;
	struct ibv_driver *driver;
	struct ibv_device *dev;
	char ibdev_name[64];

	attr = sysfs_get_classdev_attr(verbs_dev, "ibdev");
	if (!attr) {
		fprintf(stderr, PFX "Warning: no ibdev class attr for %s\n",
			verbs_dev->name);
		return;
	}

	sscanf(attr->value, "%63s", ibdev_name);

	ib_dev = sysfs_open_class_device("infiniband", ibdev_name);
	if (!ib_dev) {
		fprintf(stderr, PFX "Warning: no infiniband class device %s for %s\n",
			attr->value, verbs_dev->name);
		return;
	}

	dlist_for_each_data(driver_list, driver, struct ibv_driver) {
		dev = driver->init_func(verbs_dev);
		if (dev) {
			dev->dev    = verbs_dev;
			dev->ibdev  = ib_dev;
			dev->driver = driver;

			dlist_push(device_list, dev);

			return;
		}
	}

	fprintf(stderr, PFX "Warning: no driver for %s\n", verbs_dev->name);
}

static int check_abi_version(void)
{
	char path[256];
	char val[16];
	int ver;

	if (sysfs_get_mnt_path(path, sizeof path)) {
		fprintf(stderr, PFX "Fatal: couldn't find sysfs mount.\n");
		return -1;
	}

	strncat(path, "/class/infiniband_verbs/abi_version", sizeof path);

	if (sysfs_read_attribute_value(path, val, sizeof val)) {
		fprintf(stderr, PFX "Fatal: couldn't read uverbs ABI version.\n");
		return -1;
	}

	ver = strtol(val, NULL, 10);

	if (ver != IB_USER_VERBS_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: kernel ABI version %d "
			"doesn't match library version %d.\n",
			ver, IB_USER_VERBS_ABI_VERSION);
		return -1;
	}

	return 0;
}


static void INIT ibverbs_init(void)
{
	const char *user_path;
	char *wr_path, *dir;
	struct sysfs_class *cls;
	Dlist *verbs_dev_list;
	struct sysfs_class_device *verbs_dev;

	driver_list = dlist_new(sizeof (struct ibv_driver));
	device_list = dlist_new(sizeof (struct ibv_device));
	if (!driver_list || !device_list) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device/driver list.\n");
		abort();
	}

	if (ibv_init_mem_map())
		return;

	/*
	 * Check if a driver is statically linked, and if so load it first.
	 */
	load_driver(NULL);

	user_path = getenv(OPENIB_DRIVER_PATH_ENV);
	if (user_path) {
		wr_path = strdupa(user_path);
		while ((dir = strsep(&wr_path, ";:")))
			find_drivers(dir);
	}

	find_drivers(default_path);

	cls = sysfs_open_class("infiniband_verbs");
	if (!cls) {
		fprintf(stderr, PFX "Fatal: couldn't open infiniband sysfs class.\n");
		return;
	}

	if (check_abi_version())
		return;

	verbs_dev_list = sysfs_get_class_devices(cls);
	if (!verbs_dev_list) {
		fprintf(stderr, PFX "Fatal: no infiniband class devices found.\n");
		return;
	}

	dlist_for_each_data(verbs_dev_list, verbs_dev, struct sysfs_class_device)
		init_drivers(verbs_dev);
}
