/*
 * Copyright (c) 2014,2016 Intel Corporation. All Rights Reserved
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

#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <syslog.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>

#include <systemd/sd-daemon.h>
#include <libudev.h>

static struct udev *g_udev;
static struct udev_monitor *g_mon;

#define SYS_HOSTNAME "/proc/sys/kernel/hostname"
#define SYS_INFINIBAND "/sys/class/infiniband"
#define DEFAULT_ND_FORMAT "%h %d"

static char *g_nd_format = NULL;
static bool debugging;

static void newline_to_null(char *str)
{
	char *term = index(str, '\n');
	if (term)
		*term = '\0';
}

static void strip_domain(char *str)
{
	char *term = index(str, '.');
	if (term)
		*term = '\0';
}

static __attribute__((format(printf, 1, 2))) void dbg_log(const char *fmt, ...)
{
	va_list ap;

	if (!debugging)
		return;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

static void build_node_desc(char *dest, size_t len,
		     const char *device, const char *hostname)
{
	char *end = dest + len-1;
	const char *field;
	char *src = g_nd_format;

	while (*src && (dest < end)) {
		if (*src != '%') {
			*dest++ = *src++;
		} else {
			src++;
			switch (*src) {
			case 'h':
				field = hostname;
				while (*field && (*field != '.') && (dest < end))
					*dest++ = *field++;
				break;
			case 'd':
				field = device;
				while (*field && (dest < end))
					*dest++ = *field++;
				break;
			}
			src++;
		}
	}
	*dest = 0;
}

static int update_node_desc(const char *device, const char *hostname, int force)
{
	int rc;
	char nd[128];
	char new_nd[64];
	char nd_file[PATH_MAX];
	FILE *f;

	snprintf(nd_file, sizeof(nd_file), SYS_INFINIBAND "/%s/node_desc",
			device);
	nd_file[sizeof(nd_file)-1] = '\0';

	f = fopen(nd_file, "r+");
	if (!f)
		return -EIO;

	if (!fgets(nd, sizeof(nd), f)) {
		syslog(LOG_ERR, "Failed to read %s\n", nd_file);
		rc = -EIO;
		goto error;
	}
	newline_to_null(nd);

	build_node_desc(new_nd, sizeof(new_nd), device, hostname);

	if (!force && strncmp(new_nd, nd, sizeof(new_nd)) == 0) {
		dbg_log("%s: no change (%s)\n", device, new_nd);
	} else {
		dbg_log("%s: change (%s) -> (%s)\n", device, nd, new_nd);
		rewind(f);
		fprintf(f, "%s", new_nd);
	}

	rc = 0;
error:
	fclose(f);
	return rc;
}

static void set_rdma_node_desc(const char *hostname, int force)
{
	DIR *class_dir;
	struct dirent *dent;

	class_dir = opendir(SYS_INFINIBAND);
	if (!class_dir) {
		syslog(LOG_ERR, "Failed to open " SYS_INFINIBAND);
		return;
	}

	while ((dent = readdir(class_dir))) {
		if (dent->d_name[0] == '.')
			continue;

		if (update_node_desc(dent->d_name, hostname, force))
			syslog(LOG_DEBUG, "set Node Description failed on %s\n",
			       dent->d_name);
	}

	closedir(class_dir);
}

static void read_hostname(int fd, char *name, size_t len)
{
	memset(name, 0, len);
	if (read(fd, name, len-1) >= 0) {
		newline_to_null(name);
		strip_domain(name);
	} else {
		syslog(LOG_ERR, "Read %s Failed\n", SYS_HOSTNAME);
	}
	lseek(fd, 0, SEEK_SET);
}

static void setup_udev(void)
{
	g_udev = udev_new();
	if (!g_udev) {
		syslog(LOG_ERR, "udev_new failed\n");
		return;
	}
}

static int get_udev_fd(void)
{
	g_mon = udev_monitor_new_from_netlink(g_udev, "udev");
	if (!g_mon) {
		syslog(LOG_ERR, "udev monitoring failed\n");
		return -1;
	}

	udev_monitor_filter_add_match_subsystem_devtype(g_mon, "infiniband", NULL);
	udev_monitor_enable_receiving(g_mon);
	return udev_monitor_get_fd(g_mon);
}

static void process_udev_event(int ud_fd, const char *hostname)
{
	struct udev_device *dev;

	dev = udev_monitor_receive_device(g_mon);
	if (dev) {
		const char *device = udev_device_get_sysname(dev);
		const char *action = udev_device_get_action(dev);

		dbg_log("Device event: %s, %s, %s\n",
			udev_device_get_subsystem(dev), device, action);

		if (device && action &&
		    (!strncmp(action, "add", sizeof("add")) ||
		     !strncmp(action, "move", sizeof("add"))))
			if (update_node_desc(device, hostname, 1))
				syslog(LOG_DEBUG, "set Node Description failed on %s\n",
				       device);

		udev_device_unref(dev);
	}
}

static void monitor(bool systemd)
{
	char hostname[128];
	int hn_fd;
	struct pollfd fds[2];
	int numfds = 1;
	int ud_fd;

	hn_fd = open(SYS_HOSTNAME, O_RDONLY);
	if (hn_fd < 0) {
		syslog(LOG_ERR, "Open %s Failed exiting\n",
			SYS_HOSTNAME);
		exit(EXIT_FAILURE);
	}

	read_hostname(hn_fd, hostname, sizeof(hostname));
	set_rdma_node_desc((const char *)hostname, 1);

	fds[0].fd = hn_fd;
	fds[0].events = 0;

	ud_fd = get_udev_fd();
	if (ud_fd >= 0)
		numfds = 2;

	fds[1].fd = ud_fd;
	fds[1].events = POLLIN;

	if (systemd)
		sd_notify(0, "READY=1");

	while (1) {
		if (poll(fds, numfds, -1) <= 0) {
			syslog(LOG_ERR, "Poll %s failed; exiting\n", SYS_HOSTNAME);
			exit(EXIT_FAILURE);
		}

		if (fds[0].revents != 0) {
			read_hostname(hn_fd, hostname, sizeof(hostname));
			dbg_log("Hostname event: %s\n", hostname);
			set_rdma_node_desc((const char *)hostname, 0);
		}

		if (fds[1].revents != 0)
			process_udev_event(ud_fd, hostname);
	}
}

int main(int argc, char *argv[])
{
	bool foreground = false;
	bool systemd = false;

	openlog(NULL, LOG_NDELAY | LOG_CONS | LOG_PID, LOG_DAEMON);

	while (1) {
		static const struct option long_opts[] = {
			{ "foreground",   0, NULL, 'f' },
			{ "systemd",      0, NULL, 's' },
			{ "help",         0, NULL, 'h' },
			{ "debug",        0, NULL, 'd' },
			{ }
		};

		int c = getopt_long(argc, argv, "fh", long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			foreground = true;
			break;
		case 's':
			systemd = true;
			break;
		case 'd':
			debugging = true;
			break;
		case 'h':
			printf("rdma-ndd [options]\n");
			printf("    See 'man rdma-ndd' for details\n");
			return 0;
		default:
			break;

		}
	}

	if (!foreground && !systemd) {
		if (daemon(0, 0) != 0) {
			syslog(LOG_ERR, "Failed to daemonize\n");
			return EXIT_FAILURE;
		}
	}

	setup_udev();

	g_nd_format = getenv("RDMA_NDD_ND_FORMAT");
	if (g_nd_format && strncmp("", g_nd_format, strlen(g_nd_format)) != 0)
		g_nd_format = strdup(g_nd_format);
	else
		g_nd_format = strdup(DEFAULT_ND_FORMAT);

	dbg_log("Node Descriptor format (%s)\n", g_nd_format);

	monitor(systemd);

	return 0;
}
