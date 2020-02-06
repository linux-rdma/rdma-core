// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/* Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <dirent.h>
#include <syslog.h>
#include <rdma/rdma_netlink.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/pci_regs.h>
#include <util/rdma_nl.h>

/*
 * Rename modes:
 * NAME_FALLBACK - Try to name devices in the following order:
 *                 by->onboard -> by-pci -> by-guid -> kernel
 * NAME_KERNEL - leave name as kernel provided
 * NAME_PCI - based on PCI/slot/function location
 * NAME_GUID - based on node GUID
 * NAME_ONBOARD - based on-board device index
 *
 * The stable names are combination of device type technology and rename mode.
 * Infiniband - ib*
 * RoCE - roce*
 * iWARP - iw*
 * OPA - opa*
 * Default (unknown protocol) - rdma*
 *
 * Example:
 * NAME_PCI
 *  pci = 0000:00:0c.4
 *  Device type = IB
 *  mlx5_0 -> ibp0s12f4
 * NAME_GUID
 *  GUID = 5254:00c0:fe12:3455
 *  Device type = RoCE
 *  mlx5_0 -> rocex525400c0fe123455
 * NAME_ONBOARD
 *  Index = 3
 *  Device type = OPA
 *  hfi1_1 -> opao3
 */

struct data {
	const char *curr;
	char *prefix;
	uint64_t node_guid;
	char *name;
	int idx;
};

static bool debug_mode;
#define pr_err(args...) syslog(LOG_ERR, ##args)
#define pr_dbg(args...)                                                        \
	do {                                                                   \
		if (debug_mode)                                                \
			syslog(LOG_ERR, ##args);                               \
	} while (0)

#define ONBOARD_INDEX_MAX (16*1024-1)
static int by_onboard(struct data *d)
{
	char *index = NULL;
	char *acpi = NULL;
	unsigned int o;
	FILE *fp;
	int ret;

	/*
	 * ACPI_DSM - device specific method for naming
	 * PCI or PCI Express device
	 */
	ret = asprintf(&acpi, "/sys/class/infiniband/%s/device/acpi_index",
		      d->curr);
	if (ret < 0)
		return -ENOMEM;

	/* SMBIOS type 41 - Onboard Devices Extended Information */
	ret = asprintf(&index, "/sys/class/infiniband/%s/device/index", d->curr);
	if (ret < 0) {
		index = NULL;
		ret = -ENOMEM;
		goto out;
	}

	fp = fopen(acpi, "r");
	if (!fp)
		fp = fopen(index, "r");
	if (!fp) {
		pr_dbg("%s: Device is not embedded onboard\n", d->curr);
		ret = -ENOENT;
		goto out;
	}

	ret = fscanf(fp, "%u", &o);
	fclose(fp);
	/* https://github.com/systemd/systemd/blob/master/src/udev/udev-builtin-net_id.c#L263 */
	if (!ret || o > ONBOARD_INDEX_MAX) {
		pr_err("%s: Onboard index %d and ret %d\n", d->curr, o, ret);
		ret = -ENOENT;
		goto out;
	}

	ret = asprintf(&d->name, "%so%u", d->prefix, o);
	if (ret < 0) {
		pr_err("%s: Failed to allocate name with prefix %s and onboard index %d\n",
		       d->curr, d->prefix, o);
		ret = -ENOENT;
		d->name = NULL;
	}
	ret = 0;
out:
	free(index);
	free(acpi);
	return ret;
}

static int find_sun(char *devname, char *pci)
{
	char bof[256], tmp[256];
	struct dirent *dent;
	char *slots;
	DIR *dir;
	int ret;

	ret = asprintf(&slots, "%s/subsystem/slots", devname);
	if (ret < 0)
		return 0;

	ret = 0;
	dir = opendir(slots);
	if (!dir)
		goto err_dir;

	if (sscanf(pci, "%s.%s", bof, tmp) != 2)
		goto out;

	while ((dent = readdir(dir))) {
		char *str, address[256];
		FILE *fp;
		int i;

		if (dent->d_name[0] == '.')
			continue;
		i = atoi(dent->d_name);
		if (i <= 0)
			continue;

		ret = asprintf(&str, "%s/%s/address", slots, dent->d_name);
		if (ret < 0) {
			ret = 0;
			goto out;
		}

		fp = fopen(str, "r");
		free(str);
		if (!fp) {
			ret = 0;
			goto out;
		}

		ret = fscanf(fp, "%s", address);
		fclose(fp);

		if (ret != 1) {
			ret = 0;
			goto out;
		}

		if (!strcmp(bof, address)) {
			ret = i;
			break;
		}
	}
out:
	closedir(dir);
err_dir:
	free(slots);
	return ret;
}

static int is_pci_multifunction(char *devname)
{
	char c[64] = {};
	char *config;
	FILE *fp;
	int ret;

	ret = asprintf(&config, "%s/config", devname);
	if (ret < 0)
		return 0;

	fp = fopen(config, "r");
	free(config);
	if (!fp)
		return 0;

	ret = fread(c, 1, sizeof(c), fp);
	fclose(fp);
	if (ret != sizeof(c))
		return 0;

	/* bit 0-6 header type, bit 7 multi/single function device */
	return c[PCI_HEADER_TYPE] & 0x80;
}

static int is_pci_ari_enabled(char *devname)
{
	int ret, a;
	char *ari;
	FILE *fp;

	ret = asprintf(&ari, "%s/ari_enabled", devname);
	if (ret < 0)
		return 0;

	fp = fopen(ari, "r");
	free(ari);
	if (!fp)
		return 0;

	ret = fscanf(fp, "%d", &a);
	fclose(fp);
	return (ret) ? a == 1 : 0;
}

struct pci_info {
	char *pcidev;

	unsigned int domain;
	unsigned int bus;
	unsigned int slot;
	unsigned int func;
	unsigned int sun;
	unsigned int vf;
	bool valid_vf;
};

static int fill_pci_info(struct data *d, struct pci_info *p)
{
	char buf[256] = {};
	char *pci;
	int ret;

	ret = readlink(p->pcidev, buf, sizeof(buf)-1);
	if (ret == -1 || ret == sizeof(buf))
		return -EINVAL;

	buf[ret] = 0;

	pci = basename(buf);
	/*
	 * pci = 0000:00:0c.0
	 */
	ret = sscanf(pci, "%x:%x:%x.%u", &p->domain, &p->bus, &p->slot,
		     &p->func);
	if (ret != 4) {
		pr_err("%s: Failed to read PCI BOF\n", d->curr);
		return -ENOENT;
	}

	if (is_pci_ari_enabled(p->pcidev)) {
		/*
		 * ARI devices support up to 256 functions on a single device
		 * ("slot"), and interpret the traditional 5-bit slot and 3-bit
		 * function number as a single 8-bit function number, where the
		 * slot makes up the upper 5 bits.
		 *
		 * https://github.com/systemd/systemd/blob/master/src/udev/udev-builtin-net_id.c#L344
		 */
		p->func += p->slot * 8;
		pr_dbg("%s: This is ARI device, new PCI BOF is %04x:%02x:%02x.%u\n",
		       d->curr, p->domain, p->bus, p->slot, p->func);
	}

	p->sun = find_sun(p->pcidev, pci);

	return 0;
}

static int get_virtfn_info(struct data *d, struct pci_info *p)
{
	struct pci_info vf = {};
	char *physfn_pcidev;
	struct dirent *dent;
	DIR *dir;
	int ret;

	/* Check if this is a virtual function. */
	ret = asprintf(&physfn_pcidev, "%s/physfn", p->pcidev);
	if (ret < 0)
		return -ENOMEM;

	/* We are VF, get VF number and replace pcidev to point to PF */
	dir = opendir(physfn_pcidev);
	if (!dir) {
		/*
		 * -ENOENT means that we are already in PF
		 *  and pcidev points to right PCI.
		 */
		ret = (errno == ENOENT) ? 0 : -ENOMEM;
		goto err_free;
	}

	p->valid_vf = true;
	vf.pcidev = p->pcidev;
	ret = fill_pci_info(d, &vf);
	if (ret)
		goto err_dir;

	while ((dent = readdir(dir))) {
		const char *s = "virtfn";
		struct pci_info v = {};

		if (strncmp(dent->d_name, s, strlen(s)) ||
		    strlen(dent->d_name) == strlen(s))
			continue;

		ret = asprintf(&v.pcidev, "%s/%s", physfn_pcidev, dent->d_name);
		if (ret < 0) {
			ret = -ENOMEM;
			goto err_dir;
		}
		ret = fill_pci_info(d, &v);
		free(v.pcidev);
		if (ret) {
			ret = -ENOMEM;
			goto err_dir;
		}
		if (vf.func == v.func) {
			p->vf = atoi(&dent->d_name[6]);
			break;
		}
	}

	p->pcidev = physfn_pcidev;
	closedir(dir);

	return 0;

err_dir:
	closedir(dir);
err_free:
	free(physfn_pcidev);
	return ret;
}

static int by_pci(struct data *d)
{
	struct pci_info p = {};
	char *subsystem;
	char buf[256] = {};
	char *subs;
	int ret;

	ret = asprintf(&subsystem, "/sys/class/infiniband/%s/device/subsystem",
		      d->curr);
	if (ret < 0)
		return -ENOMEM;

	ret = readlink(subsystem, buf, sizeof(buf)-1);
	if (ret == -1 || ret == sizeof(buf)) {
		ret = -EINVAL;
		goto out;
	}
	buf[ret] = 0;

	subs = basename(buf);
	if (strcmp(subs, "pci")) {
		/* Ball out virtual devices */
		pr_dbg("%s: Non-PCI device (%s) was detected\n", d->curr, subs);
		ret = -EINVAL;
		goto out;
	}

	/* Real devices */
	ret = asprintf(&p.pcidev, "/sys/class/infiniband/%s/device", d->curr);
	if (ret < 0) {
		ret = -ENOMEM;
		p.pcidev = NULL;
		goto out;
	}

	ret = get_virtfn_info(d, &p);
	if (ret)
		goto out;

	ret = fill_pci_info(d, &p);
	if (ret) {
		pr_err("%s: Failed to fill PCI device information\n", d->curr);
		goto out;
	}

	d->name = calloc(256, sizeof(char));
	if (!d->name) {
		ret = -ENOMEM;
		goto out;
	}

	ret = sprintf(d->name, "%s", d->prefix);
	if (ret == -1) {
		ret = -EINVAL;
		goto out;
	}

	if (p.domain > 0) {
		ret = sprintf(buf, "P%u", p.domain);
		if (ret == -1) {
			ret = -ENOMEM;
			goto out;
		}
		strcat(d->name, buf);
	}

	if (p.sun > 0)
		ret = sprintf(buf, "s%u", p.sun);
	else
		ret = sprintf(buf, "p%us%u", p.bus, p.slot);
	if (ret == -1) {
		ret = -ENOMEM;
		goto out;
	}

	strcat(d->name, buf);

	if (p.func > 0 || is_pci_multifunction(p.pcidev)) {
		ret = sprintf(buf, "f%u", p.func);
		if (ret == -1) {
			ret = -ENOMEM;
			goto out;
		}
		strcat(d->name, buf);

		if (p.valid_vf) {
			ret = sprintf(buf, "v%u", p.vf);
			if (ret == -1) {
				ret = -ENOMEM;
				goto out;
			}
			strcat(d->name, buf);
		}
	}
	ret = 0;
out:
	free(p.pcidev);
	free(subsystem);
	if (ret) {
		free(d->name);
		d->name = NULL;
	}

	return ret;
}

static int by_guid(struct data *d)
{
	uint16_t vp[4];
	int ret = -1;

	if (!d->node_guid)
		/* virtual devices start without GUID */
		goto out;

	memcpy(vp, &d->node_guid, sizeof(uint64_t));
	ret = asprintf(&d->name, "%sx%04x%04x%04x%04x", d->prefix, vp[3], vp[2],
		       vp[1], vp[0]);
out:
	if (ret == -1) {
		d->name = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int device_rename(struct nl_sock *nl, struct data *d)
{
	struct nlmsghdr *hdr;
	struct nl_msg *msg;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
			RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_SET),
			0, 0);
	if (!hdr) {
		ret = -ENOMEM;
		goto nla_put_failure;
	}

	NLA_PUT_U32(msg, RDMA_NLDEV_ATTR_DEV_INDEX, d->idx);
	NLA_PUT_STRING(msg, RDMA_NLDEV_ATTR_DEV_NAME, d->name);
	ret = nl_send_auto(nl, msg);
	if (ret < 0)
		return ret;
nla_put_failure:
	nlmsg_free(msg);
	return (ret < 0) ? ret : 0;
}

static int get_nldata_cb(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct data *d = data;
	int ret;

	ret = nlmsg_parse(hdr, 0, tb, RDMA_NLDEV_ATTR_MAX - 1, rdmanl_policy);
	if (ret < 0)
		return NL_STOP;

	if (!tb[RDMA_NLDEV_ATTR_DEV_NAME] || !tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_NODE_GUID])
		return NL_STOP;

	ret = strcmp(d->curr, nla_get_string(tb[RDMA_NLDEV_ATTR_DEV_NAME]));
	if (ret)
		return NL_OK;

	if (tb[RDMA_NLDEV_ATTR_DEV_PROTOCOL])
		d->prefix = strdup(
			nla_get_string(tb[RDMA_NLDEV_ATTR_DEV_PROTOCOL]));
	if (!d->prefix)
		ret = asprintf(&d->prefix, "rdma");
	if (ret < 0)
		return NL_STOP;

	d->idx = nla_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	d->node_guid = nla_get_u64(tb[RDMA_NLDEV_ATTR_NODE_GUID]);
	return NL_STOP;
}

enum name_policy {
	NAME_KERNEL = 1 << 0,
	NAME_PCI = 1 << 1,
	NAME_GUID = 1 << 2,
	NAME_ONBOARD = 1 << 3,
	NAME_ERROR = 1 << 8
};

static int str2policy(const char *np)
{
	if (!strcmp(np, "NAME_KERNEL"))
		return NAME_KERNEL;
	if (!strcmp(np, "NAME_PCI"))
		return NAME_PCI;
	if (!strcmp(np, "NAME_GUID"))
		return NAME_GUID;
	if (!strcmp(np, "NAME_ONBOARD"))
		return NAME_ONBOARD;
	if (!strcmp(np, "NAME_FALLBACK"))
		return NAME_ONBOARD | NAME_PCI;
	return NAME_ERROR;
};

int main(int argc, char **argv)
{
	struct data d = { .idx = -1 };
	struct nl_sock *nl;
	int ret = -1;
	int np, opt;

	if (argc < 3)
		goto err;

	while ((opt = getopt(argc, argv, "v")) >= 0) {
		switch (opt) {
		case 'v':
			debug_mode = true;
			break;
		default:
			goto err;
		}
	}

	argc -= optind;
	argv += optind;

	d.curr = argv[0];

	np = str2policy(argv[1]);
	if (np & NAME_ERROR) {
		pr_err("%s: Unknown policy %s\n", d.curr, argv[1]);
		goto err;
	}

	pr_dbg("%s: Requested policy is %s\n", d.curr, argv[1]);

	if (np & NAME_KERNEL) {
		pr_dbg("%s: Leave kernel names, do nothing\n", d.curr);
		/* Do nothing */
		exit(0);
	}

	nl = rdmanl_socket_alloc();
	if (!nl) {
		pr_err("%s: Failed to allocate netlink socket\n", d.curr);
		goto err;
	}

	if (rdmanl_get_devices(nl, get_nldata_cb, &d)) {
		pr_err("%s: Failed to connect to NETLINK_RDMA\n", d.curr);
		goto out;
	}

	if (d.idx == -1 || !d.prefix) {
		pr_err("%s: Failed to get current device name and index\n",
		       d.curr);
		goto out;
	}

	ret = -1;
	if (np & NAME_ONBOARD)
		ret = by_onboard(&d);
	if (ret && (np & NAME_PCI))
		ret = by_pci(&d);
	if (ret && (np & NAME_GUID))
		ret = by_guid(&d);
	if (ret)
		goto out;

	ret = device_rename(nl, &d);
	if (ret) {
		pr_err("%s: Device rename to %s failed with error %d\n", d.curr,
		       d.name, ret);
		goto out;
	}
	pr_dbg("%s: Successfully renamed device to be %s\n", d.curr, d.name);

	printf("%s\n", d.name);
	free(d.name);

out:
	free(d.prefix);
	nl_socket_free(nl);
err:
	ret = (ret) ? 1 : 0;
	exit(ret);
}
