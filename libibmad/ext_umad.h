/*
* SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
*
* NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
* property and proprietary rights in and to this material, related
* documentation and any modifications thereto. Any use, reproduction,
* disclosure or distribution of this material and related documentation
* without an express license agreement from NVIDIA CORPORATION or
* its affiliates is strictly prohibited.
*/


#ifndef EXT_UMAD_H_
#define EXT_UMAD_H_

#include <infiniband/umad.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief represents SMI/GSI HCA device.
 *
 */
typedef struct ext_umad_device {
	char         name[UMAD_CA_NAME_LEN];
	uint32_t     ports[UMAD_CA_MAX_PORTS];
	uint32_t     numports;
	uint32_t     preferred_port;
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
 *
 * @return the number of devices filled, -1 on error.
 */
int ext_umad_get_cas(ext_umad_ca_t cas[], size_t max);

/**
 * @brief get extended ca and port nums based on device name and portnum.
 *        the given portnum addresses a port in the given device name (might be smi or gsi).
 *
 * @param devname[input] - ca (smi, gsi or legacy) name to search, or NULL to find the first one.
 * @param out[output]    - extended ca found (optional)
 * @param portnum        - a port number of a port in 'devname'.
 *					0 for the first SMI and GSI with identical GUIDs.
 * @return 0 if a device and ports were found, 1 otherwise
 */
int ext_umad_get_ca_by_name(const char *devname, uint8_t portnum, ext_umad_ca_t *ca);

#ifdef __cplusplus
}
#endif

#endif    /* EXT_UMAD_H_ */
