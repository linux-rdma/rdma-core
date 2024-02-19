/*
 * Copyright (c) 2023-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under the terms of the
 * OpenIB.org BSD license included below:
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


#ifndef IBNETDISC_EXT_UMAD_H_
#define IBNETDISC_EXT_UMAD_H_

#include <infiniband/umad.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ext_umad_device {
	char         name[UMAD_CA_NAME_LEN];
	uint32_t     ports[UMAD_CA_MAX_PORTS];
} ext_umad_device_t;

/**
 * @brief represents SMI and GSI pairs on an HCA.
 *        on legacy CAs both devices should have the same name.
 */
typedef struct ext_umad_ca {
	ext_umad_device_t smi;
	ext_umad_device_t gsi;
} ext_umad_ca_t;

/**
 * @brief fill a user allocated struct of extended cas according to umad data.
 *
 * @param cas[out]
 * @param max - maximum amount of devices to fill.
 * @return the number of devices filled, -1 on error.
 */
int ibnd_ext_umad_get_cas(ext_umad_ca_t cas[], size_t max);

/**
 * @brief get extended ca and port nums based on device name and portnum.
 *          the given portnum addresses a port in the given device name (might be smi or gsi).
 *
 * @param devname[input] - ca (smi, gsi or legacy) name to search, or NULL to find the first one.
 * @param out[output] - extended ca found (optional)
 * @param portnum - a port number of a port in 'devname'.
 *					0 for the first SMI and GSI with identical GUIDs.
 * @return 0 if a device and ports were found, 1 otherwise
 */
int ibnd_ext_umad_get_ca_by_name(const char *devname, uint8_t portnum, ext_umad_ca_t *out);

#ifdef __cplusplus
}
#endif

#endif    /* IBNETDISC_EXT_UMAD_H_ */
