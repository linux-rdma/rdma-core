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
#include <unistd.h>
#include <sys/types.h>

#include "ibverbs.h"

#ifndef OPENIB_DRIVER_PATH_ENV
#  define OPENIB_DRIVER_PATH_ENV "OPENIB_DRIVER_PATH"
#endif

HIDDEN int abi_ver;

static char default_path[] = DRIVER_PATH;
static const char *user_path;

static struct ibv_driver *driver_list;

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
	driver->next      = driver_list;
	driver_list       = driver;
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

static struct ibv_device *init_drivers(struct sysfs_class_device *verbs_dev)
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
		return NULL;
	}

	sscanf(attr->value, "%63s", ibdev_name);

	ib_dev = sysfs_open_class_device("infiniband", ibdev_name);
	if (!ib_dev) {
		fprintf(stderr, PFX "Warning: no infiniband class device %s for %s\n",
			attr->value, verbs_dev->name);
		return NULL;
	}

	for (driver = driver_list; driver; driver = driver->next) {
		dev = driver->init_func(verbs_dev);
		if (dev) {
			dev->dev    = verbs_dev;
			dev->ibdev  = ib_dev;
			dev->driver = driver;

			return dev;
		}
	}

	fprintf(stderr, PFX "Warning: no userspace device-specific driver found for %s\n"
		"	driver search path: ", verbs_dev->name);
	if (user_path)
		fprintf(stderr, "%s:", user_path);
	fprintf(stderr, "%s\n", default_path);

	return NULL;
}

static int check_abi_version(void)
{
	char path[256];
	char val[16];

	if (sysfs_get_mnt_path(path, sizeof path)) {
		fprintf(stderr, PFX "Fatal: couldn't find sysfs mount.\n");
		return -1;
	}

	strncat(path, "/class/infiniband_verbs/abi_version", sizeof path);

	if (sysfs_read_attribute_value(path, val, sizeof val)) {
		fprintf(stderr, PFX "Fatal: couldn't read uverbs ABI version.\n");
		return -1;
	}

	abi_ver = strtol(val, NULL, 10);

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION ||
	    abi_ver > IB_USER_VERBS_MAX_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: kernel ABI version %d "
			"doesn't match library version %d.\n",
			abi_ver, IB_USER_VERBS_MAX_ABI_VERSION);
		return -1;
	}

	return 0;
}


HIDDEN int ibverbs_init(struct ibv_device ***list)
{
	char *wr_path, *dir;
	struct sysfs_class *cls;
	struct dlist *verbs_dev_list;
	struct sysfs_class_device *verbs_dev;
	struct ibv_device *device;
	struct ibv_device **new_list;
	int num_devices = 0;
	int list_size = 0;

	*list = NULL;

	if (ibv_init_mem_map())
		return 0;

	find_drivers(default_path);

	/*
	 * Only follow the path passed in through the calling user's
	 * environment if we're not running SUID.
	 */
	if (getuid() == geteuid()) {
		user_path = getenv(OPENIB_DRIVER_PATH_ENV);
		if (user_path) {
			wr_path = strdupa(user_path);
			while ((dir = strsep(&wr_path, ";:")))
				find_drivers(dir);
		}
	}

	/*
	 * Now check if a driver is statically linked.  Since we push
	 * drivers onto our driver list, the last driver we find will
	 * be the first one we try.
	 */
	load_driver(NULL);

	cls = sysfs_open_class("infiniband_verbs");
	if (!cls) {
		fprintf(stderr, PFX "Fatal: couldn't open sysfs class 'infiniband_verbs'.\n");
		return 0;
	}

	if (check_abi_version())
		return 0;

	verbs_dev_list = sysfs_get_class_devices(cls);
	if (!verbs_dev_list) {
		fprintf(stderr, PFX "Fatal: no infiniband class devices found.\n");
		return 0;
	}

	dlist_for_each_data(verbs_dev_list, verbs_dev, struct sysfs_class_device) {
		device = init_drivers(verbs_dev);
		if (device) {
			if (list_size <= num_devices) {
				list_size = list_size ? list_size * 2 : 1;
				new_list = realloc(*list, list_size * sizeof (struct ibv_device *));
				if (!new_list)
					goto out;
				*list = new_list;
			}
			*list[num_devices++] = device;
		}
	}

out:
	return num_devices;
}
