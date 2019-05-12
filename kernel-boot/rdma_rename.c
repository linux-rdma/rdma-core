// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/* Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <rdma/rdma_netlink.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/pci_regs.h>

/*
 * Rename modes:
 * NAME_FALLBACK - Try to name devices in the following order:
 *                 by->onboard -> by-pci -> by-guid -> kernel
 * NAME_KERNEL - leave name as kernel provided
 * NAME_PCI - based on PCI/slot/function location
 * NAME_GUID - based on system image GUID
 * NAME_ONBOARD - based on-board device index
 *
 * The stable names are combination of device type technology and rename mode.
 * Infiniband - ib*
 * RoCE - roce*
 * iWARP - iw*
 * OPA - opa*
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

static struct nla_policy policy[RDMA_NLDEV_ATTR_MAX] = {
	[RDMA_NLDEV_ATTR_DEV_INDEX] = { .type = NLA_U32 },
	[RDMA_NLDEV_ATTR_NODE_GUID] = { .type = NLA_U64 },
#ifdef NLA_NUL_STRING
	[RDMA_NLDEV_ATTR_DEV_NAME] = { .type = NLA_NUL_STRING },
	[RDMA_NLDEV_ATTR_DEV_PROTOCOL] = { .type = NLA_NUL_STRING },
#endif /* NLA_NUL_STRING */
};

struct data {
	const char *curr;
	const char *prefix;
	uint64_t sys_image_guid;
	char *name;
	int idx;
};

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
		ret = -ENOENT;
		goto out;
	}

	ret = fscanf(fp, "%u", &o);
	fclose(fp);
	/* https://github.com/systemd/systemd/blob/master/src/udev/udev-builtin-net_id.c#L263 */
	if (!ret || o > ONBOARD_INDEX_MAX) {
		ret = -ENOENT;
		goto out;
	}

	ret = asprintf(&d->name, "%so%u", d->prefix, o);
	if (ret < 0) {
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

static int by_pci(struct data *d)
{
	long domain, bus, slot, func, sun;
	char *devpath = NULL;
	char *subsystem;
	char buf[256] = {};
	char *pci, *subs;
	int ret;

	ret = asprintf(&subsystem, "/sys/class/infiniband/%s/device/subsystem",
		      d->curr);
	if (ret < 0)
		return -ENOMEM;

	ret = readlink(subsystem, buf, sizeof(buf)-1);
	if (ret == -1) {
		ret = -EINVAL;
		goto out;
	}

	subs = basename(buf);
	if (strcmp(subs, "pci")) {
		/* Ball out virtual devices */
		ret = -EINVAL;
		goto out;
	}

	/* Real devices */
	ret = asprintf(&devpath, "/sys/class/infiniband/%s/device", d->curr);
	if (ret < 0) {
		ret = -ENOMEM;
		devpath = NULL;
		goto out;
	}

	ret = readlink(devpath, buf, sizeof(buf)-1);
	if (ret == -1) {
		ret = -EINVAL;
		goto out;
	}
	pci = basename(buf);
	/*
	 * pci = 0000:00:0c.0
	 */
	if (sscanf(pci, "%lx:%lx:%lx.%lu", &domain, &bus, &slot, &func) != 4) {
		ret = -ENOENT;
		goto out;
	}

	if (is_pci_ari_enabled(devpath))
		/*
		 * ARI devices support up to 256 functions on a single device
		 * ("slot"), and interpret the traditional 5-bit slot and 3-bit
		 * function number as a single 8-bit function number, where the
		 * slot makes up the upper 5 bits.
		 *
		 * https://github.com/systemd/systemd/blob/master/src/udev/udev-builtin-net_id.c#L344
		 */
		func += slot * 8;

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

	if (domain > 0) {
		ret = sprintf(buf, "P%ld", domain);
		if (ret == -1) {
			ret = -ENOMEM;
			goto out;
		}
		strcat(d->name, buf);
	}

	sun = find_sun(devpath, pci);
	if (sun > 0)
		ret = sprintf(buf, "s%ld", sun);
	else
		ret = sprintf(buf, "p%lds%ld", bus, slot);
	if (ret == -1) {
		ret = -ENOMEM;
		goto out;
	}

	strcat(d->name, buf);

	if (func > 0 || is_pci_multifunction(devpath)) {
		ret = sprintf(buf, "f%ld", func);
		if (ret == -1) {
			ret = -ENOMEM;
			goto out;
		}
		strcat(d->name, buf);
	}
	ret = 0;
out:
	free(devpath);
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

	if (!d->sys_image_guid)
		/* virtual devices start without GUID */
		goto out;

	memcpy(vp, &d->sys_image_guid, sizeof(uint64_t));
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
	int ret;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
			RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_SET),
			0, 0);
	if (!hdr) {
		ret = -ENOMEM;
		goto out;
	}

	ret = nla_put_u32(msg, RDMA_NLDEV_ATTR_DEV_INDEX, d->idx);
	if (ret)
		goto out;
	ret = nla_put_string(msg, RDMA_NLDEV_ATTR_DEV_NAME, d->name);
	if (ret)
		goto out;
	ret = nl_send_auto(nl, msg);
	if (ret < 0)
		return ret;
out:
	nlmsg_free(msg);
	return (ret < 0) ? ret : 0;
}

static int get_nldata_cb(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[RDMA_NLDEV_ATTR_MAX] = {};
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct data *d = data;
	int ret;

	ret = nlmsg_parse(hdr, 0, tb, RDMA_NLDEV_ATTR_MAX - 1, policy);
	if (ret < 0)
		return NL_STOP;

	if (!tb[RDMA_NLDEV_ATTR_DEV_NAME] || !tb[RDMA_NLDEV_ATTR_DEV_INDEX] ||
	    !tb[RDMA_NLDEV_ATTR_SYS_IMAGE_GUID] ||
	    !tb[RDMA_NLDEV_ATTR_DEV_PROTOCOL])
		return NL_STOP;

	ret = strcmp(d->curr, nla_get_string(tb[RDMA_NLDEV_ATTR_DEV_NAME]));
	if (ret)
		return NL_OK;

	d->prefix = nla_get_string(tb[RDMA_NLDEV_ATTR_DEV_PROTOCOL]);
	d->idx = nla_get_u32(tb[RDMA_NLDEV_ATTR_DEV_INDEX]);
	d->sys_image_guid = nla_get_u64(tb[RDMA_NLDEV_ATTR_SYS_IMAGE_GUID]);
	return NL_STOP;
}

static int get_nldata(struct nl_sock *nl, struct data *data)
{
	struct nl_cb *cb;
	int ret;

	ret = nl_send_simple(
		nl, RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET),
		NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, NULL, 0);
	if (ret < 0)
		return ret;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_nldata_cb, (void *)data);

	do {
		ret = nl_recvmsgs(nl, cb);
	} while (ret > 0);

	return ret;
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

int main(int argc, const char *argv[])
{
	struct data d = { .idx = -1 };
	struct nl_sock *nl;
	int ret = -1;
	int np;

	if (argc != 3)
		goto err;

	np = str2policy(argv[2]);
	if (np & NAME_ERROR)
		goto err;

	if (np & NAME_KERNEL)
		/* Do nothing */
		exit(0);

	nl = nl_socket_alloc();
	if (!nl)
		goto err;

	if (nl_connect(nl, NETLINK_RDMA))
		goto out;

	d.curr = argv[1];
	ret = get_nldata(nl, &d);
	if (ret || d.idx == -1)
		goto out;

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
	if (ret)
		goto out;

	printf("%s\n", d.name);
	free(d.name);

out:
	nl_socket_free(nl);
err:
	ret = (ret) ? 1 : 0;
	exit(ret);
}
