/*
 * Copyright (c) 2023-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
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


#include <infiniband/ibnetdisc_ext_umad.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPMASK_IS_SM_DISABLED 0x400

typedef typeof(((struct umad_port *)0)->port_guid) umad_guid_t;

/**
 * @brief struct to save the number of ports with a specific port GUID
 */
struct port_guid_port_count {
	umad_guid_t port_guid;
	uint8_t   count;
};

/**
 * @brief A mapping between a port GUID, and the extended ca that has ports with this GUID.
 *        Used to search the correct extended ca for a given port.
 */
struct guid_ext_ca_mapping {
	umad_guid_t port_guid;
	ext_umad_ca_t *ext_ca;
};

/**
 * @brief search the 'counts' array for a struct with a given GUID / the first
 *	  empty struct if GUID was not found
 *
 * @param counts[in]
 * @param max - size of counts
 * @param port_guid
 * @param index[out]
 * @return true - a struct was found, 'index' contains it's index
 * @return false - a struct was not found, 'index' contains the
		   first unused index in counts / the last index if counts is full.
 */
static bool find_port_guid_count(struct port_guid_port_count counts[], size_t max,
						  umad_guid_t port_guid, size_t *index)
{
	for (size_t i = 0; i < max; ++i) {
		if (counts[i].port_guid == 0) {
			*index = i;
			return false;
		}
		if (counts[i].port_guid == port_guid) {
			*index = i;
			return true;
		}
	}

	*index = max;
	return false;
}

/**
 * @brief count the number of ports that hold each GUID.
 *
 * @param legacy_ca_names[in] - ca names given by umad_get_cas_names
 * @param num_cas - number of cas returned by umad_get_cas_names
 * @param counts[out] - each entry in this array contains a port guid and
			the number of ports with that guid.
 * @param max - maximum output array size. new GUIDs will be
		ignored after the maximum amount was added.
 * @return number of guids counted (output array length)
 */
static int count_ports_by_guid(char legacy_ca_names[][UMAD_CA_NAME_LEN], size_t num_cas,
						struct port_guid_port_count counts[], size_t max)
{
	// how many unique port GUIDs were added
	size_t num_of_guid = 0;

	memset(counts, 0, max * sizeof(struct port_guid_port_count));
	for (size_t c_idx = 0; c_idx < num_cas; ++c_idx) {
		umad_ca_t curr_ca;

		if (umad_get_ca(legacy_ca_names[c_idx], &curr_ca) < 0)
			continue;

		for (size_t p_idx = 1; p_idx < (size_t)curr_ca.numports + 1; ++p_idx) {
			umad_port_t *p_port = curr_ca.ports[p_idx];
			size_t count_idx = 0;

			if (!p_port)
				continue;

			if (find_port_guid_count(counts, max, p_port->port_guid, &count_idx)) {
				// port GUID already has a count struct
				++counts[count_idx].count;
			} else {
				// add a new count struct for this GUID.
				// if the maximum amount was already added, do nothing.
				if (count_idx != max) {
					counts[count_idx].port_guid = p_port->port_guid;
					counts[count_idx].count = 1;
					++num_of_guid;
				}
			}
		}

		umad_release_ca(&curr_ca);
	}

	return num_of_guid;
}

/**
 * @brief return the amount of ports with the same port GUID as the one given.
 *        simply searches the counts array for the correct GUID.
 *
 * @param guid
 * @param counts[in] - an array holding each guid and it's count.
 * @param max_guids - maximum amount of entries in 'counts' array.
 * @return size_t
 */
static uint8_t get_port_guid_count(umad_guid_t guid, const struct port_guid_port_count counts[],
							size_t max_guids)
{
	for (size_t i = 0; i < max_guids; ++i) {
		if (counts[i].port_guid == guid)
			return counts[i].count;
	}

	return 0;
}

static bool is_smi_disabled(umad_port_t *p_port)
{
	return (be32toh(p_port->capmask) & CAPMASK_IS_SM_DISABLED);
}

/**
 * @brief Get a pointer to the device in which a planarized port
 *		  with 'port_guid' should be inserted.
 *
 *        Search the mapping array for the given port_guid.
 *	  if found, return the result pointer.
 *        if not found, return the first non-initialized 'dev'
 *	  array index (or NULL if the array is full),
 *        add a new mapping for the given port, and advance 'added' counters.
 *
 * @param port_guid
 * @param mapping[input, output] - search this array for the given port GUID.
 * @param map_max - maximum size of the mapping array
 * @param map_added - amount of mappings in 'mapping'.
 *		      will be increased if a new mapping is added.
 * @param devs[input] - the array from which the index will be returned
 * @param devs_max - maximum size of 'devs' array
 * @param devs_added - amount of initialized devices in 'devs' array.
 *		       will be changed if a new device is added.
 * @return address of the device that corresponds to the given GUID.
 *	   NULL if not found and 'devs' is full.
 */
static ext_umad_ca_t *get_ext_ca_from_arr_by_guid(umad_guid_t port_guid,
					struct guid_ext_ca_mapping mapping[],
					size_t map_max, size_t *map_added,
					ext_umad_ca_t devs[],
					size_t devs_max, size_t *devs_added)
{
	ext_umad_ca_t *dev = NULL;
	// attempt to find the port guid in the mapping
	for (size_t i = 0; i < *map_added; ++i) {
		if (mapping[i].port_guid == port_guid)
			return mapping[i].ext_ca;
	}

	// attempt to add a new mapping/device
	if (*map_added >= map_max || *devs_added >= devs_max)
		return NULL;

	dev = &devs[*devs_added];
	mapping[*map_added].port_guid = port_guid;
	mapping[*map_added].ext_ca = dev;
	(*devs_added)++;
	(*map_added)++;

	return dev;
}

/**
 * @brief add a new port to a device's port numbers array (zero terminated).
 *        set the device's name if it doesn't have one.
 *
 * @param dev[output] - devices the port number should be added to.
 * @param p_port[input] - the port whose number will be added to the
 *			  list (and potentially ca name)
 */
static void add_new_port(ext_umad_device_t *dev, umad_port_t *p_port)
{
	for (size_t i = 0; i < UMAD_CA_MAX_PORTS; ++i) {
		if (dev->ports[i] == 0) {
			dev->ports[i] = p_port->portnum;
			break;
		}
	}
	if (!dev->name[0])
		memcpy(dev->name, p_port->ca_name, UMAD_CA_NAME_LEN);
}

int ibnd_ext_umad_get_cas(ext_umad_ca_t cas[], size_t max)
{
	size_t added_devices = 0, added_mappings = 0;
	char legacy_ca_names[UMAD_MAX_DEVICES][UMAD_CA_NAME_LEN] = {};
	struct port_guid_port_count counts[UMAD_MAX_PORTS] = {};
	struct guid_ext_ca_mapping mapping[UMAD_MAX_PORTS] = {};

	memset(cas, 0, sizeof(ext_umad_ca_t) * max);
	int cas_found = umad_get_cas_names(legacy_ca_names, UMAD_MAX_DEVICES);

	if (cas_found < 0)
		return 0;

	count_ports_by_guid(legacy_ca_names, cas_found, counts, UMAD_MAX_PORTS);

	for (size_t c_idx = 0; c_idx < (size_t)cas_found; ++c_idx) {
		umad_ca_t curr_ca;

		if (umad_get_ca(legacy_ca_names[c_idx], &curr_ca) < 0)
			continue;

		for (size_t p_idx = 1; p_idx < (size_t)curr_ca.numports + 1; ++p_idx) {
			umad_port_t *p_port = curr_ca.ports[p_idx];
			uint8_t guid_count = 0;

			if (!p_port)
				continue;

			guid_count = get_port_guid_count(curr_ca.ports[p_idx]->port_guid,
								counts, UMAD_MAX_PORTS);
			ext_umad_ca_t *dev = get_ext_ca_from_arr_by_guid(p_port->port_guid,
								mapping, UMAD_MAX_PORTS,
								&added_mappings, cas,
								max, &added_devices);
				if (!dev)
					continue;
			if (guid_count > 1) {
				// planarized port
				add_new_port(is_smi_disabled(p_port) ?
						&dev->gsi : &dev->smi, p_port);
			} else if (guid_count == 1) {
				if (!is_smi_disabled(p_port))
					add_new_port(&dev->smi, p_port);

				// all ports are GSI ports in legacy HCAs
				add_new_port(&dev->gsi, p_port);
			} else {
				return -1;
			}
		}

		umad_release_ca(&curr_ca);
	}

	return added_devices;
}

int ibnd_ext_umad_get_ca_by_name(const char *devname, uint8_t portnum, ext_umad_ca_t *out)
{
	int rc = 1;
	int num_cas = 0;
	ext_umad_ca_t ext_cas[UMAD_MAX_PORTS] = {};
	size_t i = 0;
	bool is_devname_gsi = false;

	num_cas = ibnd_ext_umad_get_cas(ext_cas, UMAD_MAX_PORTS);
	if (num_cas <= 0)
		return num_cas;

	for (i = 0; i < (size_t)num_cas; ++i) {
		if (!ext_cas[i].gsi.name[0] || !ext_cas[i].smi.name[0] ||
				!ext_cas[i].gsi.ports[0] || !ext_cas[i].smi.ports[0])
			continue;

		if (devname) {
			if (strncmp(ext_cas[i].gsi.name, devname, UMAD_CA_NAME_LEN)
				&& strncmp(ext_cas[i].smi.name, devname, UMAD_CA_NAME_LEN)) {
				// name doesn't match - keep searching
				continue;
			}
		}

		if (portnum) {
			// check that the device given by "devname" has a port number "portnum"
			// (if devname doesn't exist, assume smi port is given)
			is_devname_gsi = (devname && \
				!strncmp(devname, ext_cas[i].gsi.name, UMAD_CA_NAME_LEN));
			ext_umad_device_t *devname_dev = is_devname_gsi ? \
					&ext_cas[i].gsi : &ext_cas[i].smi;
			bool found_port = false;

			for (size_t port_idx = 0; port_idx < UMAD_CA_MAX_PORTS; ++port_idx) {
				if (!devname_dev->ports[port_idx])
					break;
				if (devname_dev->ports[port_idx] == portnum)
					found_port = true;
			}

			// couldn't find portnum - keep searching
			if (!found_port)
				continue;
		}

		rc = 0;
		break;
	}

	if (!rc) {
		if (out)
			*out = ext_cas[i];
	}

	return rc;
}
