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

static const char default_path[] = DRIVER_PATH;
static const char *user_path;

static struct ibv_sysfs_dev *sysfs_dev_list;
static struct ibv_driver *driver_list;

static void find_sysfs_devs(void)
{
	struct sysfs_class *cls;
	struct dlist *verbs_dev_list;
	struct sysfs_class_device *verbs_dev;
	struct ibv_sysfs_dev *dev;

	cls = sysfs_open_class("infiniband_verbs");
	if (!cls) {
		fprintf(stderr, PFX "Fatal: couldn't open sysfs class 'infiniband_verbs'.\n");
		return;
	}

	verbs_dev_list = sysfs_get_class_devices(cls);
	if (!verbs_dev_list) {
		fprintf(stderr, PFX "Fatal: no infiniband class devices found.\n");
		return;
	}

	dlist_for_each_data_rev(verbs_dev_list, verbs_dev, struct sysfs_class_device) {
		dev = malloc(sizeof *dev);
		if (!dev) {
			fprintf(stderr, PFX "Warning: couldn't allocate device for %s\n",
				verbs_dev->name);
			continue;
		}

		dev->verbs_dev   = verbs_dev;
		dev->next        = sysfs_dev_list;
		dev->have_driver = 0;
		sysfs_dev_list   = dev;
	}
}

__attribute__((weak))
struct ibv_device *openib_driver_init(struct sysfs_class_device *dev)
{
        return NULL;
}

static void load_driver(char *so_path)
{
	void *dlhandle;
	ibv_driver_init_func init_func;
	struct ibv_driver *driver;

	dlhandle = dlopen(so_path, RTLD_NOW);
	if (!dlhandle) {
		fprintf(stderr, PFX "Warning: couldn't load driver %s: %s\n",
			so_path, dlerror());
		return;
	}

	dlerror();
	init_func = dlsym(dlhandle, "openib_driver_init");
	if (dlerror() != NULL || !init_func) {
		dlclose(dlhandle);
		return;
	}

	driver = malloc(sizeof *driver);
	if (!driver) {
		fprintf(stderr, PFX "Warning: couldn't allocate driver for %s\n", so_path);
		dlclose(dlhandle);
		return;
	}

	driver->init_func = init_func;
	driver->next      = driver_list;
	driver_list       = driver;
}

static void find_drivers(const char *dir)
{
	size_t len = strlen(dir);
	glob_t so_glob;
	char *pat;
	int ret;
	int i;

	if (!len)
		return;

	while (len && dir[len - 1] == '/')
		--len;

	asprintf(&pat, "%.*s/*.so", (int) len, dir);

	ret = glob(pat, 0, NULL, &so_glob);
	free(pat);

	if (ret) {
		if (ret != GLOB_NOMATCH)
			fprintf(stderr, PFX "Warning: couldn't search %s\n", pat);
		return;
	}

	for (i = 0; i < so_glob.gl_pathc; ++i)
		load_driver(so_glob.gl_pathv[i]);

	globfree(&so_glob);
}

static struct ibv_device *try_driver(ibv_driver_init_func init_func,
				     struct sysfs_class_device *verbs_dev)
{
	struct sysfs_class_device *ib_dev;
	struct ibv_device *dev;
	char ibdev_name[64];

	if (ibv_read_sysfs_file(verbs_dev->path, "ibdev",
				ibdev_name, sizeof ibdev_name) < 0) {
		fprintf(stderr, PFX "Warning: no ibdev class attr for %s\n",
			verbs_dev->name);
		return NULL;
	}

	ib_dev = sysfs_open_class_device("infiniband", ibdev_name);
	if (!ib_dev) {
		fprintf(stderr, PFX "Warning: no infiniband class device %s for %s\n",
			ibdev_name, verbs_dev->name);
		return NULL;
	}

	dev = init_func(verbs_dev);
	if (dev) {
		dev->dev    = verbs_dev;
		dev->ibdev  = ib_dev;
		dev->driver = NULL;
	}

	return dev;
}

static int check_abi_version(void)
{
	const char *path;
	char value[8];

	path = ibv_get_sysfs_path();
	if (!path) {
		fprintf(stderr, PFX "Fatal: couldn't find sysfs mount.\n");
		return -1;
	}

	if (ibv_read_sysfs_file(path, "class/infiniband_verbs/abi_version",
				value, sizeof value) < 0) {
		fprintf(stderr, PFX "Fatal: couldn't read uverbs ABI version.\n");
		return -1;
	}

	abi_ver = strtol(value, NULL, 10);

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION ||
	    abi_ver > IB_USER_VERBS_MAX_ABI_VERSION) {
		fprintf(stderr, PFX "Fatal: kernel ABI version %d "
			"doesn't match library version %d.\n",
			abi_ver, IB_USER_VERBS_MAX_ABI_VERSION);
		return -1;
	}

	return 0;
}

static void add_device(struct ibv_device *dev,
		       struct ibv_device ***dev_list,
		       int *num_devices,
		       int *list_size)
{
	struct ibv_device **new_list;

	if (*list_size <= *num_devices) {
		*list_size = *list_size ? *list_size * 2 : 1;
		new_list = realloc(*dev_list, *list_size * sizeof (struct ibv_device *));
		if (!new_list)
			return;
		*dev_list = new_list;
	}

	(*dev_list)[(*num_devices)++] = dev;
}

HIDDEN int ibverbs_init(struct ibv_device ***list)
{
	char *wr_path, *dir;
	struct ibv_sysfs_dev *sysfs_dev, *next_dev;
	struct ibv_device *device;
	struct ibv_driver *driver;
	int num_devices = 0;
	int list_size = 0;
	int no_driver = 0;
	int statically_linked = 0;

	*list = NULL;

	if (check_abi_version())
		return 0;

	if (ibv_init_mem_map())
		return 0;

	find_sysfs_devs();

	/*
	 * First check if a driver statically linked in can support
	 * all the devices.  This is needed to avoid dlopen() in the
	 * all-static case (which will break because we end up with
	 * both a static and dynamic copy of libdl).
	 */
	for (sysfs_dev = sysfs_dev_list; sysfs_dev; sysfs_dev = sysfs_dev->next) {
		device = try_driver(openib_driver_init, sysfs_dev->verbs_dev);
		if (device) {
			add_device(device, list, &num_devices, &list_size);
			sysfs_dev->have_driver = 1;
		} else
			++no_driver;
	}

	if (!no_driver)
		goto out;

	/*
	 * Check if we can dlopen() ourselves.  If this fails,
	 * libibverbs is probably statically linked into the
	 * executable, and we should just give up, since trying to
	 * dlopen() a driver module will fail spectacularly (loading a
	 * driver .so will bring in dynamic copies of libibverbs and
	 * libdl to go along with the static copies the executable
	 * has, which quickly leads to a crash.
	 */
	{
		void *hand = dlopen(NULL, RTLD_NOW);
		if (!hand) {
			fprintf(stderr, PFX "Warning: dlopen(NULL) failed, "
				"assuming static linking.\n");
			statically_linked = 1;
			goto out;
		}
		dlclose(hand);
	}

	find_drivers(default_path);

	/*
	 * Only use path passed in through the calling user's
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

	for (sysfs_dev = sysfs_dev_list; sysfs_dev; sysfs_dev = sysfs_dev->next) {
		if (sysfs_dev->have_driver)
			continue;
		for (driver = driver_list; driver; driver = driver->next) {
			device = try_driver(driver->init_func, sysfs_dev->verbs_dev);
			if (device) {
				add_device(device, list, &num_devices, &list_size);
				sysfs_dev->have_driver = 1;
			}
		}
	}

out:
	for (sysfs_dev = sysfs_dev_list, next_dev = sysfs_dev->next;
	     sysfs_dev;
	     sysfs_dev = next_dev, next_dev = sysfs_dev ? sysfs_dev->next : NULL) {
		if (!sysfs_dev->have_driver) {
			fprintf(stderr, PFX "Warning: no userspace device-specific "
				" driver found for %s\n", sysfs_dev->verbs_dev->name);
			if (statically_linked)
				fprintf(stderr, "	When linking libibverbs statically, "
					"driver must be statically linked too.\n");
			else {
				fprintf(stderr, "	driver search path: ");
				if (user_path)
					fprintf(stderr, "%s:", user_path);
				fprintf(stderr, "%s\n", default_path);
			}
		}
		free(sysfs_dev);
	}

	return num_devices;
}
