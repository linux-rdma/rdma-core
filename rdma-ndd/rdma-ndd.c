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

#include <libudev.h>

struct udev *udev;
struct udev_monitor *mon;

#define SYS_HOSTNAME "/proc/sys/kernel/hostname"
#define SYS_INFINIBAND "/sys/class/infiniband"
#define DEFAULT_RETRY_RATE 60
#define DEFAULT_RETRY_COUNT 0
#define DEFAULT_ND_FORMAT "%h %d"

int failure_retry_rate = DEFAULT_RETRY_RATE;
int set_retry_cnt = DEFAULT_RETRY_COUNT;
const char *g_pidfile = NULL;
char *g_nd_format = NULL;
const char *g_config_file = RDMA_NDD_DEF_CONFIG_FILE;

static void read_rdma_ndd_config(const char *file)
{
	char buf[1024];
	FILE *config_fd = NULL;
	char *p_prefix, *p_last;
	char *name;
	char *val_str;
	struct stat statbuf;

	syslog(LOG_INFO, "Using config file (%s)\n", file);

	/* silently ignore missing config file */
	if (!file || stat(file, &statbuf))
		return;

	config_fd = fopen(file, "r");
	if (!config_fd) {
		syslog(LOG_ERR, "Config file open failed\n");
		return;
	}

	while (fgets(buf, sizeof buf, config_fd) != NULL) {
		p_prefix = strtok_r(buf, "\n", &p_last);
		if (!p_prefix)
			continue; /* ignore blank lines */

		if (*p_prefix == '#')
			continue; /* ignore comment lines */

		name = strtok_r(p_prefix, "=", &p_last);
		val_str = strtok_r(NULL, "\n", &p_last);

		if (strncmp(name, "nd_format",
				   strlen("nd_format")) == 0) {
			free(g_nd_format);
			g_nd_format = strdup(val_str);
		}
	}

	fclose(config_fd);

}

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
	if (!f) {
		syslog(LOG_ERR, "Failed to open %s\n", nd_file);
		return -EIO;
	}

	if (!fgets(nd, sizeof(nd), f)) {
		syslog(LOG_ERR, "Failed to read %s\n", nd_file);
		rc = -EIO;
		goto error;
	}
	newline_to_null(nd);

	build_node_desc(new_nd, sizeof(new_nd), device, hostname);

	if (!force && strncmp(new_nd, nd, sizeof(new_nd)) == 0) {
		syslog(LOG_INFO, "%s: no change (%s)\n", device, new_nd);
	} else {
		syslog(LOG_INFO, "%s: change (%s) -> (%s)\n",
			device, nd, new_nd);
		rewind(f);
		fprintf(f, "%s", new_nd);
	}

	rc = 0;
error:
	fclose(f);
	return rc;
}

static int set_rdma_node_desc(const char *hostname, int force)
{
	DIR *class_dir;
	struct dirent *dent;

	class_dir = opendir(SYS_INFINIBAND);
	if (!class_dir) {
		syslog(LOG_INFO, "Failed to open " SYS_INFINIBAND);
		return -ENOSYS;
	}

	while ((dent = readdir(class_dir))) {
		int retry = set_retry_cnt;
		if (dent->d_name[0] == '.')
			continue;

		while (update_node_desc(dent->d_name, hostname, force) && retry > 0) {
			syslog(LOG_ERR, "retrying set Node Description on %s\n",
				dent->d_name);
			retry--;
		}
	}

	closedir(class_dir);
	return 0;
}

static int read_hostname(int fd, char *name, size_t len)
{
	int rc;
	memset(name, 0, len);
	if (read(fd, name, len-1) >= 0) {
		newline_to_null(name);
		strip_domain(name);
		rc = 0;
	} else {
		syslog(LOG_ERR, "Read %s Failed\n", SYS_HOSTNAME);
		rc = -EIO;
	}
	return rc;
}

static void setup_udev(void)
{
	udev = udev_new();
	if (!udev) {
		syslog(LOG_ERR, "udev_new failed\n");
		return;
	}
}

static int get_udev_fd(void)
{
	mon = udev_monitor_new_from_netlink(udev, "udev");
	if (!mon) {
		syslog(LOG_ERR, "udev monitoring failed\n");
		return -1;
	}

	udev_monitor_filter_add_match_subsystem_devtype(mon, "infiniband", NULL);
	udev_monitor_enable_receiving(mon);
	return udev_monitor_get_fd(mon);
}

static void process_udev_event(int ud_fd, const char *hostname)
{
	struct udev_device *dev;

	dev = udev_monitor_receive_device(mon);
	if (dev) {
		const char *device = udev_device_get_sysname(dev);
		const char *action = udev_device_get_action(dev);

		syslog(LOG_INFO, "Device event: %s, %s, %s\n",
			udev_device_get_subsystem(dev),
			device, action);

		if (device && action
		    && strncmp(action, "add", sizeof("add")) == 0)
			update_node_desc(device, hostname, 1);

		udev_device_unref(dev);
	}
}

static void monitor(void)
{
	char hostname[128];
	int hn_fd;
	int rc;
	struct pollfd fds[2];
	int numfds = 1;
	int ud_fd;

	ud_fd = get_udev_fd();
	if (ud_fd >= 0)
		numfds = 2;

	while (1) {
		hn_fd = open(SYS_HOSTNAME, O_RDONLY);
		if (hn_fd < 0) {
			syslog(LOG_ERR,
				"Open %s Failed: retry in %d seconds\n",
				SYS_HOSTNAME, failure_retry_rate);
			sleep(failure_retry_rate);
			continue;
		}

		fds[0].fd = hn_fd;
		fds[0].events = 0;
		fds[0].revents = 0;

		fds[1].fd = ud_fd;
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		rc = poll(fds, numfds, -1);

		if (rc > 0) {
			if (read_hostname(hn_fd, hostname, sizeof(hostname)) != 0)
				hostname[0] = '\0';

			if (fds[0].revents != 0)
				syslog(LOG_ERR, "Hostname change: %s\n", hostname);

			if (fds[1].revents != 0)
				process_udev_event(ud_fd, hostname);

			rc = set_rdma_node_desc((const char *)hostname, 0);
		} else {
			syslog(LOG_ERR, "Poll %s Failed\n", SYS_HOSTNAME);
			rc = -EIO;
		}

		close(hn_fd);

		if (rc)
			sleep(failure_retry_rate);
	}
}

static void remove_pidfile(void)
{
        if (g_pidfile)
		unlink(g_pidfile);
}

static void write_pidfile(void)
{
	FILE *f;
	if (g_pidfile) {
		remove_pidfile();
		f = fopen(g_pidfile, "w");
		if (f) {
			fprintf(f, "%d\n", getpid());
			fclose(f);
		} else {
			syslog(LOG_ERR, "Failed to write pidfile : %s\n",
				g_pidfile);
			exit(errno);
		}
	}
}

int main(int argc, char *argv[])
{
	int fd;
	char hostname[128];
	int foreground = 0;

	openlog("rdma-ndd", LOG_PID | LOG_PERROR, LOG_DAEMON);

	while (1) {
		unsigned long tmp;
		int opt_idx = 0;
		static struct option long_opts[] = {
			{"retry-timer",  1, 0, 't' },
			{"retry-count",  1, 0, 'r' },
			{"foreground",   0, 0, 'f' },
			{"pidfile",      1, 0,  1  },
			{"config",       1, 0, 'z' },
			{"help",         0, 0, 'h' },
			{"version",      0, 0, 'V' },
			{0,              0, 0,  0 }
		};

		char c = getopt_long(argc, argv, "t:r:fz:hV", long_opts, &opt_idx);
		if (c == -1)
			break;

		switch (c) {
		case 't':
			tmp = strtoul(optarg, NULL, 0);
			if (tmp >= INT_MAX) {
				syslog(LOG_ERR,
				       "Invalid retry rate specified: %lu s\n",
				       tmp);
			} else {
				failure_retry_rate = (int)tmp;
			}
			break;
		case 'r':
			tmp = strtoul(optarg, NULL, 0);
			if (tmp >= INT_MAX) {
				syslog(LOG_ERR,
				       "Invalid retry count specified: %lu\n",
				       tmp);
			} else {
				set_retry_cnt = (int)tmp;
			}
			break;
		case 'f':
			foreground = 1;
			break;
		case 1:
			g_pidfile = optarg;
			break;
		case 'z':
			g_config_file = strdup(optarg);
			break;
		case '?':
		case 'h':
			printf("rdma-ndd [options]\n");
			printf("    See 'man rdma-ndd' for more details\n");
			exit(0);
			break;
		case 'V':
			printf("rdma-core release : %u\n", PACKAGE_VERSION);
			break;
		default:
			break;

		}
	}

	read_rdma_ndd_config(g_config_file);

	if (!g_nd_format)
		g_nd_format = strdup(DEFAULT_ND_FORMAT);

	if (!foreground) {
		closelog();
		openlog("rdma-ndd", LOG_PID, LOG_DAEMON);
		if (daemon(0, 0) != 0) {
			syslog(LOG_ERR, "Failed to daemonize\n");
			exit(errno);
		}
		write_pidfile();
	}

	setup_udev();

	syslog(LOG_INFO, "Node Descriptor format (%s)\n", g_nd_format);

	fd = open(SYS_HOSTNAME, O_RDONLY);
	if (read_hostname(fd, hostname, sizeof(hostname)) != 0)
		hostname[0] = '\0';
	set_rdma_node_desc((const char *)hostname, 1);
	close(fd);

	monitor();

	remove_pidfile();

	return 0;
}
